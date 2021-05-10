import os
from app.models.feedbacks import FeedbackModel
from app.models.users import UserModel
from app.models.department import DepartmentModel
from sqlalchemy import desc
import linecache

class FeedbackInstance:
    def __init__(self, feedback):
        self.feedback = feedback
        self.user = UserModel.query.filter(UserModel.id == feedback.user_id).first()
        self.dept = DepartmentModel.query.filter(DepartmentModel.id == self.user.phong).first()

    @property
    def id(self):
        return self.feedback.id

    @property
    def user_id(self):
        return self.feedback.user_id

    @property
    def content(self):
        return self.feedback.content

    @property
    def state(self):
        return self.feedback.state

    @property
    def validation(self):
        return self.__validate()

    def __validate(self):
        errors = []

        # Check something and append to errors.

        return errors
