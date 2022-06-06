from flask import abort, request
from flask_restx import Resource
from marshmallow import ValidationError

from app.api.v1.dto import RolesDto
from app.models.roles import RoleSchema
from app.models.roles_permissions import RolesPermissionsSchema
from app.services.roles import get_roles_service

ns = RolesDto.ns


role_schema = RoleSchema()
roles_schema = RoleSchema(many=True)

role_permissions_schema = RolesPermissionsSchema(many=True)

api_service = get_roles_service()


@ns.route("/<int:id>")
class RolesAPI(Resource):
    @ns.marshal_with(RolesDto.role_response)
    def get(self, id: int):
        role = api_service.get(id)
        if not role:
            abort(404)
        return role_schema.dump(role)

    def delete(self, id: int):
        result = api_service.delete(id=id)
        if result:
            return "Role id={0} deleted".format(id), 204
        return abort(404)

    def put(self, id):
        try:
            role_schema.load(request.json)
        except ValidationError as err:
            return err.messages, 400
        if not api_service.update(id, request.json):
            return abort(404)
        return "Updated role's id={0}.".format(id), 204


@ns.route("/")
class RoleAPI1(Resource):
    @ns.expect(RolesDto.role_response)
    def post(
        self,
    ):
        try:
            role_schema.load(request.json)
            role_id = api_service.create(request.json)
        except ValidationError as err:
            return err.messages, 400
        return "Created role's id={0}.".format(role_id), 201


@ns.route("/<int:id>/permissions")
class RolePermissionsAPI(Resource):
    @ns.expect(RolesDto.role_permissions_req)
    def post(self, id: int):
        api_service.add_permissions(id, dict(request.json)["ids"])
        return "Add permissions to role.id={0}.".format(id), 200

    @ns.expect(RolesDto.role_permissions_req)
    def delete(self, id: int):
        result = api_service.delete_permissions(id, dict(request.json)["ids"])
        return ("Role id={0} deleted {1} permissions".format(id, result), 200)
