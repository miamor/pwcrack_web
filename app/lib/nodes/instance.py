import os
from app.lib.models.nodes import NodeModel
from app.lib.models.sessions import SessionModel
from app.lib.models.hashcat import HashcatHistoryModel
from sqlalchemy import desc
import linecache

class NodeInstance:
    def __init__(self, node):
        self.node = node
        self.sessions = SessionModel.query.filter(SessionModel.node_id == self.id).all()
        self.isUp = False

    @property
    def id(self):
        return self.node.id

    @property
    def num_sessions(self):
        return len(self.sessions)

    @property
    def name(self):
        return self.node.name

    @property
    def hostname(self):
        return self.node.hostname

    @property
    def port(self):
        return self.node.port

    @property
    def username(self):
        return self.node.username

    @property
    def password(self):
        return self.node.password

    @property
    def active(self):
        return self.node.active

    @property
    def validation(self):
        return self.__validate()
    

    def __validate(self):
        errors = []

        # First check if hashes have been uploaded.

        return errors

    @property
    def hashcat_history(self):
        return HashcatHistoryModel.query.filter(
            HashcatHistoryModel.node_id == self.id
        ).order_by(desc(HashcatHistoryModel.id)).all()
