from flask import request
from flask_login import login_user
from app.models.api import ApiKeys
from app.models.users import UserModel
from sqlalchemy import and_


class ApiAuth:
    def auth(self, auto_login_user):
        apikey = request.headers['X-PwCrack-Auth'].strip() if 'X-PwCrack-Auth' in request.headers else ''
        # print('[ApiAuth][auth] apikey', apikey)
        if len(apikey) == 0:
            return False

        user = self.__auth(apikey)
        if user is False:
            return False

        if auto_login_user:
            login_user(user)

        return True

    def __auth(self, apikey):
        if len(apikey) == 0:
            return False

        key = ApiKeys.query.filter(and_(ApiKeys.apikey == apikey, ApiKeys.enabled == True)).first()
        if not key:
            return False

        user = UserModel.query.filter(UserModel.id == key.user_id).first()
        if not user:
            return False

        return user
