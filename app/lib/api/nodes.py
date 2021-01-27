from app.lib.api.base import ApiBase
from app.lib.base.provider import Provider
from app.lib.api.definitions.new_node import NewNode
from app.lib.api.definitions.node import Node


class ApiNode(ApiBase):
    def create(self):
        required_fields = ['name', 'hostname', 'port', 'username', 'password']
        data = self.get_json(required_fields)
        if data is False:
            return self.send_error_response(5000, 'Missing fields',
                                            'Required fields are: ' + ', '.join(required_fields))

        provider = Provider()
        nodes = provider.nodes()

        node = nodes.create(data['name'], data['hostname'], data['port'], data['username'], data['password'])
        if node is None:
            return self.send_error_response(5002, 'Could not create node', '')

        new_node = NewNode()
        new_node.id = node.id

        return self.send_valid_response(new_node)

    def get_all(self):
        provider = Provider()
        nodes = provider.nodes()

        nodes = nodes.get()

        data = []
        for node in nodes:
            api_node = self.__get_api_node(node)
            data.append(api_node)

        return self.send_valid_response(data)

    def get(self, node_id):
        provider = Provider()
        nodes = provider.nodes()

        node = nodes.get(node_id=node_id)
        if not node:
            return self.send_access_denied_response()

        api_node = self.__get_api_node(node[0])
        return self.send_valid_response(api_node)
