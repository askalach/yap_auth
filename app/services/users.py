import logging
from functools import lru_cache
from http import HTTPStatus
from locale import strcoll
from pathlib import Path
from typing import Optional

from flask_jwt_extended.utils import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
)
from flask_sqlalchemy import SQLAlchemy
from loguru import logger
from sqlalchemy.exc import IntegrityError

from app import db, jwt
from app.config.settings import settings
from app.models.history import UsersHistory
from app.models.roles import Roles
from app.models.schemas import UserHistory as UserHistorySchema
from app.models.users import Users
from app.models.users_roles import UserRoles
from app.services.auth_decorators import user_has
from app.services.base import BaseStorage
from app.services.redis import get_redis_storage
from app.services.utils import (
    err_resp,
    get_password_hash,
    get_random_string,
    internal_err_resp,
    message,
)

log = logging.getLogger("{0}[{1}]".format(Path(__file__).parent.name, Path(__file__).name))


@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload: dict):
    jti = jwt_payload["jti"]
    token_in_storage = get_redis_storage().get_from_storage(jti)
    return token_in_storage is not None


class UsersService:
    def __init__(self, db: SQLAlchemy, storage: BaseStorage) -> None:
        self.db = db
        self.session = db.session
        self.storage = storage

    def _add_user_to_db(self, data: dict) -> int:
        user = Users(**data)
        self.session.add(user)
        self.session.commit()
        return user.id

    def _add_default_role(self, id: int) -> None:
        user_role = UserRoles(user_id=id, role_id=Roles.query.filter_by(name=settings.default_role).first().id)
        self.session.add(user_role)
        self.session.commit()

    def _to_users_history(self, id: int, agent: str) -> None:
        history_item = UsersHistory(user_id=id, user_agent=agent)
        self.session.add(history_item)
        self.session.commit()

    def _response_with_tokens(self, id: int, msg: str) -> dict:
        resp = message(True, msg)
        resp["access_token"] = create_access_token(identity=id)
        resp["refresh_token"] = create_refresh_token(identity=id)
        resp["user"] = id

        return resp

    def _response_without_tokens(self, id: int, msg: str) -> dict:
        resp = message(True, msg)
        resp["user"] = id

        return resp

    def register(self, payload: dict, agent: str) -> tuple:
        email = payload["email"]

        # Check if the email is taken
        if Users.query.filter_by(email=email).first() is not None:
            return err_resp("Email is already being used.", "email_taken", HTTPStatus.FORBIDDEN.value)

        # Validation
        try:
            user_id = self._add_user_to_db(payload)
            self._add_default_role(user_id)
            self._to_users_history(user_id, agent)

            return self._response_with_tokens(user_id, "User has been registered."), HTTPStatus.CREATED.value
        except Exception as e:
            logger.error(e)
            return internal_err_resp()

    def login(self, payload: dict, agent: str) -> tuple:
        email = payload["email"]
        password = payload["password"]

        try:
            # Fetch user data
            if not (user := Users.query.filter_by(email=email).first()):
                return err_resp(
                    "The email you have entered does not match any account.",
                    "email_404",
                    HTTPStatus.NOT_FOUND.value,
                )

            elif user and user.verify_password(password):
                self._to_users_history(user.id, agent)

                return self._response_with_tokens(user.id, "Successfully logged in."), HTTPStatus.OK.value

            return err_resp("Failed to log in, password may be incorrect.", "password_invalid", HTTPStatus.UNAUTHORIZED.value)

        except Exception as e:
            logger.error(e)
            return internal_err_resp()

    def login_vk(self, payload: dict, agent: str) -> tuple:
        email = payload["email"]
        if Users.query.filter_by(email=email).first():
            Users.query.filter_by(email=email).update(payload)
            self.session.commit()
        else:
            logger.info("New user")
            payload["password"] = get_random_string(12)

            user_id = self._add_user_to_db(payload)
            self._add_default_role(user_id)

        self._to_users_history(user_id, agent)

        return self._response_with_tokens(user_id, "User has logged by vk."), HTTPStatus.OK.value

    @user_has(permissions=["user"])
    def refresh(self) -> tuple:
        user_id = get_jwt_identity()

        return self._response_with_tokens(user_id, "Successfully refresh tokens."), HTTPStatus.OK.value

    @user_has(permissions=["user"])
    def logout(self, jti: str, ttype: strcoll) -> tuple:
        user_id = get_jwt_identity()
        self.storage.put_to_storage(jti, "", settings.JWT_ACCESS_TOKEN_EXPIRES)

        return self._response_without_tokens(user_id, f"{ttype.capitalize()} token successfully revoked."), HTTPStatus.OK.value

    @user_has(permissions=["user"])
    def update(self, payload: dict) -> tuple:
        user_id = get_jwt_identity()
        if "password" in payload.keys():
            payload["password_hash"] = get_password_hash(payload["password"])
            del payload["password"]
        if "email" in payload.keys():
            if Users.query.filter((Users.email == payload["email"]) & (Users.id != user_id)).first() is not None:
                return err_resp("Email is already being used.", "email_taken", HTTPStatus.FORBIDDEN.value)

        try:
            Users.query.filter_by(id=user_id).update(payload)
            self.session.commit()

            return self._response_without_tokens(user_id, "Successfully updated user info."), HTTPStatus.OK.value

        except ValueError as e:
            logger.error(e)
            return internal_err_resp()

    @user_has(permissions=["user"])
    def get_history(self, page: int) -> tuple:
        identity = get_jwt_identity()
        try:
            history_data = (
                UsersHistory.query.filter_by(user_id=identity).paginate(page, settings.ROWS_PER_PAGE, False).items
            )
            result = []
            for item in history_data:
                histoty_schema = UserHistorySchema()
                result.append(histoty_schema.dump(item))
            resp = message(True, "Successfully get user auth history.")
            resp["history"] = result
            return resp, HTTPStatus.OK.value

        except Exception as e:
            logger.error(e)
            return internal_err_resp()

    @user_has(permissions=["admin", "user"])
    def get(self, id: int) -> Optional[Users]:
        return Users.query.get_or_404(id)

    @user_has(permissions=["admin"])
    def delete(self, id: int) -> Optional[bool]:
        user = Users.query.get_or_404(id)
        self.session.delete(user)
        self.session.commit()
        return True

    @user_has(permissions=["admin"])
    def create(self, payload) -> int:
        user = Users(**payload)
        self.session.add(user)
        self.session.commit()
        return user

    @user_has(permissions=["admin"])
    def update_user(self, id, payload) -> Optional[bool]:
        try:
            if not Users.query.filter_by(id=id).update(payload):
                return False
            self.session.commit()
            return True
        except ValueError:
            return False

    @user_has(permissions=["admin"])
    def get_roles(self, id: int) -> list[Roles]:
        roles = Roles.query.join(UserRoles).filter(UserRoles.user_id == id).all()
        return roles

    @user_has(permissions=["admin"])
    def delete_roles(self, id: int, roles_id: list[int]) -> int:
        result = UserRoles.query.filter((UserRoles.user_id == id) & (UserRoles.role_id.in_(roles_id))).delete()
        db.session.commit()
        return result

    @user_has(permissions=["admin"])
    def add_roles(self, id: int, roles_id: list[int]) -> bool:

        user_roles = [UserRoles(user_id=id, role_id=role_id) for role_id in roles_id]
        try:
            db.session.bulk_save_objects(user_roles)
            db.session.commit()
        except IntegrityError as e:
            logger.error(e)
            return False
        return True


@lru_cache()
def get_users_service() -> UsersService:
    return UsersService(db, get_redis_storage())
