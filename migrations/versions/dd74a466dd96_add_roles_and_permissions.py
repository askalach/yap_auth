"""add roles and permissions

Revision ID: dd74a466dd96
Revises: 87424e5b4208
Create Date: 2022-06-07 17:22:31.552802

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import MetaData, Table

# revision identifiers, used by Alembic.
revision = "dd74a466dd96"
down_revision = "87424e5b4208"
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    # ### insert base roles and permissions

    # get metadata from current connection
    meta = MetaData(bind=op.get_bind())

    # pass in tuple with tables we want to reflect, otherwise whole database will get reflected
    meta.reflect(only=("permissions", "roles", "roles_permissions"))

    # define table representation
    permissions = Table("permissions", meta)

    op.bulk_insert(
        permissions,
        [
            {"name": "likeagod"},
            {"name": "admin"},
            {"name": "user"},
            {"name": "roles"},
            {"name": "permissions"},
        ],
    )

    roles = Table("roles", meta)
    op.bulk_insert(
        roles,
        [
            {"name": "superuser"},
            {"name": "admin"},
            {"name": "user"},
        ],
    )
    roles_permissions = Table("roles_permissions", meta)

    op.bulk_insert(
        roles_permissions,
        [
            {"role_id": 1, "permission_id": 1},
            {"role_id": 2, "permission_id": 2},
            {"role_id": 2, "permission_id": 4},
            {"role_id": 2, "permission_id": 5},
            {"role_id": 3, "permission_id": 3},
        ],
    )

    # ## end Alembic commands ###


def downgrade():
    # # ### commands auto generated by Alembic - please adjust! ###
    op.execute("TRUNCATE TABLE public.roles_permissions CONTINUE IDENTITY CASCADE")
    op.execute("TRUNCATE TABLE public.permissions CONTINUE IDENTITY CASCADE")
    op.execute("TRUNCATE TABLE public.roles CONTINUE IDENTITY CASCADE")

    op.execute("ALTER SEQUENCE permissions_id_seq RESTART WITH 1")
    op.execute("ALTER SEQUENCE roles_permissions_id_seq RESTART WITH 1")
    op.execute("ALTER SEQUENCE roles_id_seq RESTART WITH 1")
    # ### end Alembic commands # # #
