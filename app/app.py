from http import HTTPStatus

from flask import abort, request
from flask.wrappers import Request, Response
from flask_jwt_extended.utils import get_jwt_identity
from flask_jwt_extended.view_decorators import verify_jwt_in_request
from flask_migrate import Migrate

from app import create_app, db
from app.services.anti_ddos import get_ratelimit_service

app = create_app()
migrate = Migrate(app, db)

rate_limit = get_ratelimit_service()


@app.before_request
def before_request():
    request_id = request.headers.get("X-Request-Id")
    verify_jwt_in_request(optional=True)
    user_id = get_jwt_identity()
    key = user_id or key_from_headers(request)

    if not rate_limit.check(key):
        abort(HTTPStatus.TOO_MANY_REQUESTS.value)

    # X-Request-ID header must be in request
    if not request_id:
        raise abort(Response(status=HTTPStatus.BAD_REQUEST.value, response="X-Request-ID header must be in request."))

    from opentelemetry import trace

    current_span = trace.get_current_span()
    current_span.set_attribute("http.request_id", request_id)


def key_from_headers(request: Request) -> str:
    user_agent = request.headers.get("user-agent")
    real_ip = request.headers.get("X-Real-Ip")
    platform = request.headers.get("Sec-Ch-Ua-Platform")

    return "{0}:{1}:{2}".format(real_ip, user_agent, platform)
