import os
from app.models.users import UserModel
from app.models.department import DepartmentModel
from sqlalchemy import desc
import linecache

class UserInstance:
    def __init__(self, user):
        self.user = user
        self.dept = DepartmentModel.query.filter(DepartmentModel.id == user.phong).first()

    @property
    def id(self):
        return self.user.id

    @property
    def full_name(self):
        return self.user.full_name

    @property
    def email(self):
        return self.user.email

    @property
    def username(self):
        return self.user.username

    @property
    def password(self):
        return self.user.password

    @property
    def phone(self):
        return self.user.phone

    @property
    def phong(self):
        return self.user.phong

    @property
    def chucvu(self):
        return self.user.chucvu

    @property
    def admin(self):
        return self.user.admin

    @property
    def ldap(self):
        return self.user.ldap

    @property
    def active(self):
        return self.user.active

    @property
    def validation(self):
        return self.__validate()

    def __validate(self):
        errors = []

        # Check something and append to errors.

        return errors
