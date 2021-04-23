import os
from app.lib.models.user import UserModel
from app.lib.models.department import DepartmentModel
from sqlalchemy import desc
import linecache

class DepartmentInstance:
    def __init__(self, dep):
        self.dept = dep
        self.users = UserModel.query.filter(UserModel.phong == dep.id).all()

    @property
    def id(self):
        return self.dept.id

    @property
    def name(self):
        return self.dept.name

    @property
    def color(self):
        return self.dept.color

    @property
    def users_list(self):
        return self.users

    @property
    def users_count(self):
        return len(self.users_list)

    @property
    def validation(self):
        return self.__validate()

    def __validate(self):
        errors = []

        # Check something and append to errors.

        return errors
