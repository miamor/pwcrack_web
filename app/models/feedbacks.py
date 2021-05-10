from app import db
import datetime


class FeedbackModel(db.Model):
    __tablename__ = 'feedbacks'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    content = db.Column(db.String)
    created_at = db.Column(db.DateTime, nullable=True, default=datetime.datetime.now())
    state = db.Column(db.Integer, default=0)
