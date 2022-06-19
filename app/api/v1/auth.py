from http import HTTPStatus

from flask import request
from flask_jwt_extended.utils import get_jwt
from flask_jwt_extended.view_decorators import jwt_required
from flask_restx import Resource

from app.api.v1.dto import AuthDto
from app.services.users import get_users_service

ns = AuthDto.ns

users_service = get_users_service()


@ns.route("/registration", doc={"description": "Регистрация новых пользователей"})
class AuthRegister(Resource):

    auth_register = AuthDto.auth_register

    @ns.expect(auth_register)
    @ns.response(HTTPStatus.CREATED.value, 'User has been registered')
    @ns.response(HTTPStatus.FORBIDDEN.value, 'Email is already being used')
    def post(self):
        register_data = request.get_json()
        user_agent = request.headers.get("User-Agent")
        return users_service.register(register_data, user_agent)


@ns.route("/login", doc={"description": "Получение токенов для зарегистрированных пользователей"})
class AuthLogin(Resource):

    auth_login = AuthDto.auth_login

    @ns.expect(auth_login)
    @ns.response(HTTPStatus.OK.value, "Successfully logged in.")
    @ns.response(HTTPStatus.UNAUTHORIZED.value, "Incorrect password.")
    @ns.response(HTTPStatus.NOT_FOUND.value, "The email you have entered does not match any account.")
    def post(self):
        login_data = request.get_json()
        user_agent = request.headers.get("User-Agent")
        return users_service.login(login_data, user_agent)


@ns.route("/refresh", doc={"description": "Обновление токенов"})
class RefreshToken(Resource):
    @jwt_required(refresh=True)
    @ns.response(HTTPStatus.OK.value, "Successfully refresh tokens.")
    @ns.response(HTTPStatus.UNPROCESSABLE_ENTITY.value, "Only refresh tokens are allowed")
    def post(self):
        return users_service.refresh()


@ns.route("/logout", doc={"description": "Добавление токена в Blacklist"})
class AuthLogout(Resource):
    @jwt_required(verify_type=False)
    @ns.response(HTTPStatus.OK.value, "Token successfully revoked.")
    @ns.response(HTTPStatus.UNPROCESSABLE_ENTITY.value, "Signature verification failed.")
    def delete(self):
        token = get_jwt()
        jti = token["jti"]
        ttype = token["type"]
        return users_service.logout(jti, ttype)


@ns.route("/change", doc={"description": "Изменение данных пользователя."})
class AuthChange(Resource):

    auth_change = AuthDto.auth_change

    @jwt_required()
    @ns.response(HTTPStatus.OK.value, "Successfully updated user info.")
    @ns.response(HTTPStatus.UNPROCESSABLE_ENTITY.value, "Signature verification failed.")
    @ns.expect(auth_change)
    def post(self):
        user_data = request.get_json()
        return users_service.update(user_data)


@ns.route("/history", doc={"description": "История входов в аккаунт."})
@ns.route("/history/<int:page>", doc={"description": "История входов в аккаунт."})
class AuthHistory(Resource):
    @jwt_required()
    @ns.response(HTTPStatus.OK.value, "Successfully get user auth history.")
    @ns.response(HTTPStatus.UNPROCESSABLE_ENTITY.value, "Signature verification failed.")
    def get(self, page=1):
        return users_service.get_history(page)
