from http import HTTPStatus

import click
from flask import Blueprint
from sqlalchemy.exc import IntegrityError

from app import db
from app.models.roles import Roles
from app.models.users_roles import UserRoles
from app.services.users import UsersService, get_users_service

cli_users_bp = Blueprint("users", __name__)
cli_users_bp.cli.short_help = "Manage Auth service users"


@cli_users_bp.cli.command("superuser")
@click.argument("firstname")
@click.argument("lastname")
@click.argument("email")
@click.argument("password")
def create(firstname, lastname, email, password):
    """Create superuser for Auth service."""
    user_service: UsersService = get_users_service()

    payload = {
        "first_name": firstname,
        "last_name": lastname,
        "email": email,
        "password": password,
    }
    result = user_service.register(agent="superuser", payload=payload)
    if result[1] != HTTPStatus.CREATED.value:
        return click.echo("Can't create superuser:\n{0}".format(result))
    super_user_role: Roles = Roles.query.filter((Roles.id == 1) & (Roles.name == "superuser")).first()

    try:
        db.session.add(UserRoles(user_id=result[0]["user"], role_id=super_user_role.id))
        db.session.commit()
    except IntegrityError as e:
        return click.echo("Can't create superuser:\n{0}".format(e))
    click.echo("Super user created:\n{0}".format(result))
