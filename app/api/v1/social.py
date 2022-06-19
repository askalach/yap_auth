import email
from http import HTTPStatus
from random import seed

from flask import abort, redirect, request, session, url_for
from flask_jwt_extended.utils import get_jwt
from flask_jwt_extended.view_decorators import jwt_required
from flask_restx import Resource
from loguru import logger

from app import oauth
from app.api.v1.dto import SocialDto
from app.services.users import get_users_service

ns = SocialDto.ns

users_service = get_users_service()


def get_auth_provider(service: str):
    if service == "vk":
        provider = oauth.vk
    elif service == "yandex":
        provider = oauth.yandex
    return provider


@ns.route("/login", doc={"description": "Регистрация/вход пользователя через социальный сервис"})
class Login(Resource):
    def get(self):
        service = request.args.get("service")
        provider = get_auth_provider(service)

        if not provider:
            abort(HTTPStatus.BAD_REQUEST.value)

        session["service"] = service
        redirect_uri = url_for('Auth_v1.social_authorize', _external=True)

        return provider.authorize_redirect(redirect_uri)


@ns.route('/authorize')
class Authorize(Resource):
    @ns.deprecated
    def get(self):
        try:
            user_data = {}
            provider = get_auth_provider(session["service"])
            user = provider.authorize_access_token()

            if session["service"] == "vk":
                session['user'] = user

                user_data['email'] = user.get('email')
                user_data['token'] = user.get('access_token')

                resp = oauth.vk.get('users.get', params={'v': '5.131'})
                user_data['first_name'] = resp.json()['response'][0]['first_name']
                user_data['last_name'] = resp.json()['response'][0]['last_name']

            elif session["service"] == "yandex":

                resp = oauth.yandex.get(
                    'info',
                    params={'format': 'json'},
                    headers={'Authorization': f'OAuth {user["access_token"]}'}
                )

                session['user'] = resp.json()

                user_data['email'] = resp.json()['default_email']
                user_data['token'] = user["access_token"]
                user_data['first_name'] = resp.json()['first_name']
                user_data['last_name'] = resp.json()['last_name']

            logger.info(session["user"])

            user_agent = request.headers.get("User-Agent")

            users_service.social_login(user_data, user_agent)

        except Exception as e:
            logger.error(e)
        redirect_uri = url_for('Auth_v1.social_authorized_ok', _external=True)
        return redirect(redirect_uri)


@ns.route('/ok')
class AuthorizedOK(Resource):
    @ns.deprecated
    def get(self):
        if session["service"] == "vk":
            user_email = session["user"]["email"]
        if session["service"] == "yandex":
            user_email = session["user"]["default_email"]
        return f"{user_email} - Athorized OK"
