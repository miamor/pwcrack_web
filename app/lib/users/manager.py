import re
import os
from app.models.users import UserModel
from app.lib.users.instance import UserInstance
from app import db
from sqlalchemy import and_, or_, desc, func
import flask_bcrypt as bcrypt


class UsersManager:
    def __init__(self, password_complexity):
        self.cmd_sleep = 2
        self.last_error = ''
        self.password_complexity = password_complexity

    def __error(self, message):
        self.last_error = message

    def sanitise_name(self, name):
        return re.sub(r'\W+', '', name)

    def exists(self, username):
        return self.__get(username) is not None

    def __get(self, username):
        return UserModel.query.filter(
            or_(
                UserModel.username == username
            )
        ).first()

    def __get_by_id(self, user_id):
        return UserModel.query.filter(UserModel.id == user_id).first()

    ''' Merge with save() '''
    # def create(self, username, password, full_name, email, ldap=False, admin=False, active=True):        
    #     # name = self.sanitise_name(name)
    #     # hostname = self.sanitise_name(hostname)
    #     username = self.sanitise_name(username)

    #     # If it exists (shouldn't), return it.
    #     user = self.__get(username)
    #     if user:
    #         return user

    #     user = UserModel(
    #         username=username,
    #         password=password,
    #         full_name=full_name,
    #         email=email,
    #         phong=phong,
    #         chucvu=chucvu,
    #         phone=phone,
    #         ldap=ldap,
    #         admin=admin,
    #         active=active
    #     )
    #     db.session.add(user)
    #     db.session.commit()
    #     # In order to get the created object, we need to refresh it.
    #     db.session.refresh(user)

    #     return user

    def get_by_username(self, username):
        return UserModel.query.filter(and_(func.lower(UserModel.username) == func.lower(username))).first()

    def save(self, user_id, username, password, full_name, email, phone=None, phong=None, chucvu=None, admin=0, ldap=0, active=1):
        if user_id > 0:
            # This is a user-edit.
            user = self.get_by_id(user_id)
            if user is None:
                self.__error('Invalid User ID')
                return False
        else:
            # This is user creation.
            user = UserModel()

        # If it's an existing user and it's the LDAP status that has changed, update only that and return
        # because otherwise it will clear the fields (as the fields are not posted during the submit.
        if user_id > 0 and user.ldap != ldap:
            user.ldap = True if ldap == 1 else False
            user.active = True if active == 1 else False
            db.session.commit()
            db.session.refresh(user)
            return True

        # If there was a username update, check to see if the new username already exists.
        if username != user.username:
            u = self.get_by_username(username)
            if u:
                self.__error('Username already exists')
                return False

        if ldap == 0:
            if password != '':
                if not self.password_complexity.meets_requirements(password):
                    self.__error('Password does not meet the complexity requirements: ' + self.password_complexity.get_requirement_description())
                    return False

                # If the password is empty, it means it wasn't changed.
                password = bcrypt.generate_password_hash(password)
        else:
            # This is an LDAP user, no point in setting their password.
            password = ''

        if ldap == 0:
            # There is no point in updating these if it's an LDAP user.
            user.username = username
            if len(password) > 0:
                user.password = password
            user.full_name = full_name
            user.email = email

        user.admin = True if admin == 1 else False
        user.ldap = True if ldap == 1 else False
        user.active = True if active == 1 else False

        user.phong = phong
        user.phone = phone
        user.chucvu = chucvu

        if user_id == 0:
            db.session.add(user)

        db.session.commit()
        db.session.refresh(user)

        return True


    def get(self, user_id=0, active=None):
        query = UserModel.query

        if user_id > 0:
            query = query.filter(UserModel.id == user_id)

        if active is not None:
            query = query.filter(UserModel.active == active)

        users = query.all()

        data = []
        for user in users:
            instance = UserInstance(user)
            data.append(instance)
            # data.append(user)

        return data

    def get_user_count(self):
        return db.session.query(UserModel).count()

    def get_by_id(self, user_id):
        return UserModel.query.filter(UserModel.id == user_id).first()

    def get_admins(self, only_active):
        conditions = and_(UserModel.admin == 1)
        if only_active:
            conditions = and_(UserModel.admin == 1, UserModel.active == 1)

        return UserModel.query.filter(conditions).order_by(UserModel.id).all()

    def set_active(self, user_id, active):
        user = self.__get_by_id(user_id)
        user.active = active

        db.session.commit()
        db.session.refresh(user)
        return True

    def update(self, user_id, update_dict):
        user = self.__get_by_id(user_id)

        for key in list(update_dict.keys()):
            val = update_dict[key]
            if key == 'username':
                user.username = val
            elif key == 'password':
                user.password = val
            elif key == 'full_name':
                user.full_name = val
            elif key == 'email':
                user.email = val
            elif key == 'ldap':
                user.ldap = val
            elif key == 'admin':
                user.admin = val
            elif key == 'phong':
                user.phong = val
            elif key == 'chucvu':
                user.chucvu = val
            elif key == 'phone':
                user.phone = val
            elif key == 'active':
                user.active = val

        db.session.commit()
        db.session.refresh(user)
        return True

