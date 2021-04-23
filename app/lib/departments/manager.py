import re
import os
from app.lib.models.department import DepartmentModel
from app.lib.departments.instance import DepartmentInstance
from app import db
from sqlalchemy import and_, or_, desc


class DepartmentsManager:
    def __init__(self):
        self.cmd_sleep = 2
        self.last_error = ''

    def __error(self, message):
        self.last_error = message

    def exists(self, department_id):
        return self.__get(department_id) is not None

    def __get(self, department_id):
        return DepartmentModel.query.filter(
            or_(
                DepartmentModel.id == department_id
            )
        ).first()

    def __get_by_id(self, department_id):
        return DepartmentModel.query.filter(DepartmentModel.id == department_id).first()

    def create(self, id, name, color):
        # If it exists (shouldn't), return it.
        department = self.__get(id)
        if department:
            return department

        department = DepartmentModel(
            id=id,
            name=name,
            color=color
        )
        db.session.add(department)
        db.session.commit()
        # In order to get the created object, we need to refresh it.
        db.session.refresh(department)

        return department

    def get(self, department_id=None, active=None):
        query = DepartmentModel.query

        if department_id is not None:
            query = query.filter(DepartmentModel.id == department_id)

        if active is not None:
            query = query.filter(DepartmentModel.active == active)

        departments = query.all()

        data = []
        for department in departments:
            instance = DepartmentInstance(department)
            data.append(instance)
            # data.append(department)

        return data

    def get_department_count(self):
        return db.session.query(DepartmentModel).count()

    def get_by_id(self, department_id):
        return DepartmentModel.query.filter(DepartmentModel.id == department_id).first()

    def update(self, department_id, update_dict):
        department = self.__get_by_id(department_id)

        for key in list(update_dict.keys()):
            val = update_dict[key]
            if key == 'id':
                department.id = val
            elif key == 'name':
                department.name = val
            elif key == 'color':
                department.color = val

        db.session.commit()
        db.session.refresh(department)
        return True

    def save(self, dep_id, name, color):
        if dep_id != '0':
            # This is a user-edit.
            dept = self.get_by_id(dep_id)
            if dept is None:
                self.__error('Invalid Department ID')
                return False
        else:
            # This is department creation.
            dept = DepartmentModel()

        # If there was a username update, check to see if the new username already exists.
        if dep_id != dept.id:
            u = self.get_by_id(dep_id)
            if u:
                self.__error('ID already exists')
                return False

        dept.name = name
        dept.color = color

        if dep_id == 0:
            db.session.add(dept)

        db.session.commit()
        db.session.refresh(dept)

        return True
