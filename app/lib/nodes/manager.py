import re
import os
from app.models.nodes import NodeModel
from app.lib.nodes.instance import NodeInstance
from app import db
from sqlalchemy import and_, or_, desc
from app.utils.node_api import NodeAPI


class NodeManager:
    def __init__(self):
        self.cmd_sleep = 2

    def sanitise_name(self, name):
        return re.sub(r'\W+', '', name)

    def exists(self, name, hostname, port):
        return self.__get(name, hostname, port) is not None

    def __get(self, name, hostname, port):
        return NodeModel.query.filter(
            or_(
                NodeModel.name == name,
                and_(
                    NodeModel.hostname == hostname,
                    NodeModel.port == port
                )
            )
        ).first()

    def __get_by_id(self, node_id):
        return NodeModel.query.filter(NodeModel.id == node_id).first()

    def create(self, name, hostname, port, username, password, active=1):        
        # name = self.sanitise_name(name)
        # hostname = self.sanitise_name(hostname)
        username = self.sanitise_name(username)

        # If it exists (shouldn't), return it.
        node = self.__get(name, hostname, port)
        if node:
            return node

        node = NodeModel(
            name=name,
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            active=active
        )
        db.session.add(node)
        db.session.commit()
        # In order to get the created object, we need to refresh it.
        db.session.refresh(node)

        return node

    def get(self, node_id=0, active=None):
        query = NodeModel.query

        if node_id > 0:
            query = query.filter(NodeModel.id == node_id)

        if active is not None:
            query = query.filter(NodeModel.active == active)

        nodes = query.all()

        data = []
        for node in nodes:
            instance = NodeInstance(node)
            data.append(instance)

        return data

    def set_active(self, node_id, active):
        node = self.__get_by_id(node_id)
        node.active = active

        db.session.commit()
        db.session.refresh(node)
        return True

    def update(self, node_id, update_dict):
        node = self.__get_by_id(node_id)

        for key in list(update_dict.keys()):
            val = update_dict[key]
            if key == 'name':
                node.name = val
            elif key == 'hostname':
                node.hostname = val
            elif key == 'port':
                node.port = val
            elif key == 'username':
                node.username = val
            elif key == 'password':
                node.password = val
            elif key == 'active':
                node.active = val
            elif key == 'hashcat_binary':
                node.hashcat_binary = val
            elif key == 'hashcat_rules_path':
                node.hashcat_rules_path = val
            elif key == 'wordlists_path':
                node.wordlists_path = val
            elif key == 'hashcat_status_interval':
                node.hashcat_status_interval = val
            elif key == 'hashcat_force':
                node.hashcat_force = val
            elif key == 'uploaded_hashes_path':
                node.uploaded_hashes_path = val

        db.session.commit()
        db.session.refresh(node)
        return True

