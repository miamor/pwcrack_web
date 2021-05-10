import re
import os
from app.models.feedbacks import FeedbackModel
from app.lib.feedbacks.instance import FeedbackInstance
from app import db
from sqlalchemy import and_, or_, desc, func
import flask_bcrypt as bcrypt


class FeedbacksManager:
    def __init__(self):
        self.last_error = ''

    def __error(self, message):
        self.last_error = message

    def sanitise_name(self, name):
        return re.sub(r'\W+', '', name)

    def exists(self, user_id, content):
        return self.__get(user_id, content) is not None

    def __get(self, user_id, content):
        return FeedbackModel.query.filter(
            and_(
                FeedbackModel.content == content,
                FeedbackModel.user_id == user_id
            )
        ).first()

    def __get_by_id(self, feedback_id):
        return FeedbackModel.query.filter(FeedbackModel.id == feedback_id).first()

    def save(self, feedback_id, user_id, content, state=0):
        if feedback_id > 0:
            # This is a feedback-edit.
            feedback = self.get_by_id(feedback_id)
            if feedback is None:
                self.__error('Invalid Feedback ID')
                return False
        else:
            # This is feedback creation.
            feedback = FeedbackModel()
        
        feedback.state = state
        feedback.user_id = user_id
        feedback.content = content

        if feedback_id == 0:
            db.session.add(feedback)

        db.session.commit()
        db.session.refresh(feedback)

        return True


    def get(self, feedback_id=0, show_all=False):
        query = FeedbackModel.query

        if feedback_id > 0:
            query = query.filter(FeedbackModel.id == feedback_id)

        if show_all is False:
            query = query.filter(FeedbackModel.state == 0)

        feedbacks = query.all()

        data = []
        for feedback in feedbacks:
            instance = FeedbackInstance(feedback)
            data.append(instance)
            # data.append(feedback)

        return data

    def get_feedback_count(self):
        return db.session.query(FeedbackModel).count()

    def get_by_id(self, feedback_id):
        return FeedbackModel.query.filter(FeedbackModel.id == feedback_id).first()

    def set_state(self, feedback_id, state):
        feedback = self.__get_by_id(feedback_id)
        print('feedback', feedback, '|', state)
        feedback.state = state

        db.session.commit()
        db.session.refresh(feedback)
        return True

    def update(self, feedback_id, update_dict):
        feedback = self.__get_by_id(feedback_id)

        for key in list(update_dict.keys()):
            val = update_dict[key]
            if key == 'content':
                feedback.content = val
            elif key == 'user_id':
                feedback.user_id = val
            elif key == 'state':
                feedback.state = val

        db.session.commit()
        db.session.refresh(feedback)
        return True

