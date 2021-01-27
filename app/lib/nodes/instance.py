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
        if self.hashes_in_file == 0:
            errors.append('No hashes have been uploaded')

        # Now we check the hashtype.
        if self.hashcat.hashtype == '':
            errors.append('No hash type has been selected')

        # Check attack mode settings.
        if self.hashcat.mode == 0:
            # Do checks for wordlist attacks.
            if self.hashcat.wordlist == '':
                errors.append('No wordlist has been selected')
        else:
            # Do checks for bruteforce attacks.
            if self.hashcat.mask == '':
                errors.append('No mask has been set')

        # Check termination date
        if self.terminate_at is None:
            errors.append('No termination date has been set')

        return errors

    @property
    def hashcat_history(self):
        return HashcatHistoryModel.query.filter(
            HashcatHistoryModel.node_id == self.id
        ).order_by(desc(HashcatHistoryModel.id)).all()
