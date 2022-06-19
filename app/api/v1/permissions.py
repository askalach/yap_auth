from http import HTTPStatus

from flask import abort, request
from flask_jwt_extended.view_decorators import jwt_required
from flask_restx import Resource
from marshmallow import ValidationError

from app.api.v1.dto import PermissionsDto as PDto
from app.models.permissions import PermissionsSchema
from app.services.permissions import get_permissions_service

ns = PDto.ns

permission_schema = PermissionsSchema()
permissions_schema = PermissionsSchema(many=True)

api_service = get_permissions_service()


@ns.route("/<int:id>")
class PermissionsAPI(Resource):
    @jwt_required()
    @ns.doc(description="Получение права по id")
    @ns.marshal_with(PDto.permission_response)
    def get(self, id: int):
        permission = api_service.get(id)
        if not permission:
            abort(HTTPStatus.NOT_FOUND.value)
        return permission_schema.dump(permission)

    @jwt_required()
    @ns.doc(description="Удаление права по id")
    @ns.response(HTTPStatus.OK.value, "Permission has been deleted.")
    @ns.response(HTTPStatus.NOT_FOUND.value, "ID not found.")
    def delete(self, id: int):
        result = api_service.delete(id=id)
        if result:
            return "Permission id={0} deleted".format(id), HTTPStatus.OK.value
        return abort(HTTPStatus.NOT_FOUND.value)

    @jwt_required()
    @ns.doc(description="Изменение права по id")
    @ns.response(HTTPStatus.NO_CONTENT.value, "Permission has been updated.")
    @ns.response(HTTPStatus.NOT_FOUND.value, "ID not found.")
    def put(self, id):
        try:
            permission_schema.load(request.json)
        except ValidationError as err:
            return err.messages, HTTPStatus.BAD_REQUEST.value
        if not api_service.update(id, request.json):
            return abort(HTTPStatus.NOT_FOUND.value)
        return "Updated permission's id={0}.".format(id), HTTPStatus.NO_CONTENT.value


@ns.route("/")
class PermissionsAPI1(Resource):
    @jwt_required()
    @ns.doc(description="Добавление права")
    @ns.response(HTTPStatus.CREATED.value, "Permission has been created.")
    @ns.expect(PDto.permission_response)
    def post(self):
        try:
            permission_schema.load(request.json)
            permission_id = api_service.create(request.json)
        except ValidationError as err:
            return err.messages, HTTPStatus.BAD_REQUEST.value
        return "Created permission's id={0}.".format(permission_id), HTTPStatus.CREATED.value
