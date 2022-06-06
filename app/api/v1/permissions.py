from flask import abort, request
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
    @ns.marshal_with(PDto.permission_response)
    def get(self, id: int):
        permission = api_service.get(id)
        if not permission:
            abort(404)
        return permission_schema.dump(permission)

    def delete(self, id: int):
        result = api_service.delete(id=id)
        if result:
            return "Permission id={0} deleted".format(id), 200
        return abort(404)

    def put(self, id):
        try:
            permission_schema.load(request.json)
        except ValidationError as err:
            return err.messages, 400
        if not api_service.update(id, request.json):
            return abort(404)
        return "Updated permission's id={0}.".format(id)


@ns.route("/")
class PermissionsAPI1(Resource):
    @ns.expect(PDto.permission_response)
    def post(self):
        try:
            permission_schema.load(request.json)
            permission_id = api_service.create(request.json)
        except ValidationError as err:
            return err.messages, 400
        return "Created permission's id={0}.".format(permission_id)
