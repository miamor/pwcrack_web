from sqlalchemy import and_
from app.models.users import UserSettings
from app import db


class AccountSettingsManager:
    def save(self, user_id, name, value):
        setting = UserSettings.query.filter(and_(UserSettings.user_id == user_id, UserSettings.name == name)).first()
        if setting is None:
            setting = UserSettings(user_id=user_id, name=name, value=value)
            db.session.add(setting)
        else:
            setting.value = value

        db.session.commit()
        return True

    def get(self, user_id, name, default=None):
        setting = UserSettings.query.filter(and_(UserSettings.user_id == user_id, UserSettings.name == name)).first()
        if setting is None:
            return default
        return setting.value
