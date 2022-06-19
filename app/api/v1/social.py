from email import header

from flask import redirect, request, session, url_for
from flask_jwt_extended.utils import get_jwt
from flask_jwt_extended.view_decorators import jwt_required
from flask_restx import Resource
from loguru import logger

from app import oauth
from app.api.v1.dto import SocialDto
from app.services.users import get_users_service

ns = SocialDto.ns

users_service = get_users_service()


@ns.route("/vk", doc={"description": "Регистрация/вход пользователя через vk"})
class SocialVKLogin(Resource):
    def get(self):
        redirect_uri = url_for('Auth_v1.social_social_vk_authorize', _external=True)
        return oauth.vk.authorize_redirect(redirect_uri)


@ns.route('/vk/authorize')
class SocialVKAuthorize(Resource):
    @ns.deprecated
    def get(self):
        try:
            user_data = {}
            user = oauth.vk.authorize_access_token()
            session['user'] = user

            user_data['email'] = user.get('email')
            user_data['token'] = user.get('access_token')

            resp = oauth.vk.get('users.get', params={'v': '5.131'})
            user_data['first_name'] = resp.json()['response'][0]['first_name']
            user_data['last_name'] = resp.json()['response'][0]['last_name']

            user_agent = request.headers.get("User-Agent")

            users_service.social_login(user_data, user_agent)

        except Exception as e:
            logger.error(e)
        redirect_uri = url_for('Auth_v1.social_social_vk_authorized_ok', _external=True)
        return redirect(redirect_uri)


@ns.route('/vk/ok')
class SocialVKAuthorizedOK(Resource):
    @ns.deprecated
    def get(self):
        user = session.get('user')
        return f"{user['email']} - Athorized OK"


@ns.route("/yandex", doc={"description": "Регистрация/вход пользователя через yandex"})
class SocialYandexLogin(Resource):
    def get(self):
        redirect_uri = url_for('Auth_v1.social_social_yandex_authorize', _external=True)
        logger.info(redirect_uri)
        return oauth.yandex.authorize_redirect(redirect_uri)


@ns.route('/yandex/authorize')
class SocialYandexAuthorize(Resource):
    @ns.deprecated
    def get(self):
        try:
            user_data = {}
            user = oauth.yandex.authorize_access_token()
            logger.info(user)

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

            user_agent = request.headers.get("User-Agent")

            users_service.social_login(user_data, user_agent)

        except Exception as e:
            logger.error(e)

        redirect_uri = url_for('Auth_v1.social_social_yandex_authorized_ok', _external=True)
        return redirect(redirect_uri)


@ns.route('/yandex/ok')
class SocialYandexAuthorizedOK(Resource):
    @ns.deprecated
    def get(self):
        user = session.get('user')
        return f"{user['default_email']} - Athorized OK"
