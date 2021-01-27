import socket
import requests
from requests_toolbelt.multipart import encoder
import http.client
import ssl
import threading
#from urllib.request import Request, urlopen
import struct
import json
import base64
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

timeout_connection = 1
timeout_read = 60*10
TIMEOUT = (timeout_connection, timeout_read)

class NodeAPI:

    def __init__(self, node):
        self.ip = node.hostname
        self.port = node.port
        self.key = base64.b64encode(("%s:%s" % (node.username, node.password)).encode("ascii")).decode("ascii")
    
    def hashcat_action(self, session_name, action):
        return self.send("/session/%s/%s" % (session_name, action))

        # payload = {
        #     "session": session_name,
        #     "action": action,
        # }
        # return self.send("/hashcat_action", data=payload)

    def get_running_processes_commands(self):
        return self.send("/get_running_processes_commands")

    def create_hashcat_session(self, payload, filepaths):
        return self.post_file("/create_session", payload, filepaths=filepaths)
    
    def sync_hashcat_session(self, payload, filepaths, files=None):
        return self.post_file("/sync_hashcat_session", payload, filepaths=filepaths, files=files)
    
    def sync_session(self, payload):
        return self.send("/sync_session", payload)
    
    def get_wordlists_from_node(self):
        return self.send("/get_wordlists_from_node")
    
    def get_rules_from_node(self):
        return self.send("/get_rules_from_node")

    def is_valid_local_wordlist(self, wordlist_filename):
        return self.send("/is_valid_local_wordlist", data={'wordlist_filename': wordlist_filename})

    def is_valid_local_rule(self, rule_filename):
        return self.send("/is_valid_local_rule", data={'rule_filename': rule_filename})
    
    def update_hashcat_settings(self, update_dict):
        return self.send("/update_hashcat_settings", data=update_dict)

    def get_hashcat_info(self):
        return self.send("/hashcatInfo")


    def upload_rule(self, name, rule_file):
        payload = {
            "name": name,
            "rules": base64.b64encode(rule_file).decode(),
        }

        return self.send("/uploadRule", data=payload)

    def upload_mask(self, name, mask_file):
        payload = {
            "name": name,
            "masks": base64.b64encode(mask_file).decode(),
        }

        return self.send("/uploadMask", data=payload)

    def upload_wordlist(self, name, wordlist_file):
        payload = {
            "name": name,
            "wordlists": base64.b64encode(wordlist_file).decode(),
        }

        return self.send("/uploadWordlist", data=payload)



    def send(self, url, data=None):
        headers = {
            "Content-Type": "text/plain; charset=utf-8",
            "Accept-Encoding": "text/plain",
            "Authorization": "Basic %s" % self.key,
        }

        """
        gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # disable certif validation
        conn = http.client.HTTPSConnection(self.ip, self.port, context=gcontext, verify=False)

        if payload == None:
            conn.request("GET", url, headers=headers)
        else:
            conn.request("POST", url, "%s\r\n\r\n" % json.dumps(payload), headers)

        res = conn.getresponse()
        """

        url = "https://%s:%d/api/v1%s" % (self.ip, self.port, url)
        if data == None:
            print('[send][GET] url', url)
            res = requests.get(url, headers=headers, verify=False, timeout=TIMEOUT)
        else:
            print('[send][POST] url', url, json.dumps(data))
            res = requests.post(url, json.dumps(data), headers=headers, verify=False, timeout=TIMEOUT)

        #data = res.read()
        data = res.text

        #conn.close()
        return json.loads(data)

    def post_file(self, url, payload, filepaths, files=None):
        headers = {
            "Content-Type": "text/plain; charset=utf-8",
            "Accept-Encoding": "text/plain",
            "Authorization": "Basic %s" % self.key,
        }

        url = "https://%s:%d/api/v1%s" % (self.ip, self.port, url)
        print('[post_file] url', url)

        # form = encoder.MultipartEncoder({
        #     'json': (None, json.dumps(payload), 'application/json'),
        #     'file': ("file", open(filepath, 'rb'), 'application/octet-stream')
        # })

        if len(filepaths) > 0:
            payload['num_files'] = len(filepaths)

            enc_data = {
                'json': (None, json.dumps(payload), 'application/json'),
                # 'file': files
                # 'file': files
            }

            if payload['num_files'] > 0:
                for idx, filepath in enumerate(filepaths):
                    enc_data['file__{}'.format(idx)] = (filepath.split('/')[-1], open(filepath, 'rb'), 'application/octet-stream')
        elif files is not None and len(files) > 0:
            payload['num_files'] = len(files)

            enc_data = {
                'json': (None, json.dumps(payload), 'application/json'),
            }

            if payload['num_files'] > 0:
                for idx, file in enumerate(files):
                    enc_data['file__{}'.format(idx)] = (file.filename.split('/')[-1], file.read(), 'application/octet-stream')
        else:
            payload['num_files'] = 0
            enc_data = {
                'json': (None, json.dumps(payload), 'application/json'),
            }

            
        
        form = encoder.MultipartEncoder(enc_data)

        headers['Content-Type'] = form.content_type

        print('form', form)

        res = requests.post(url, data=form, headers=headers, verify=False)

        data = res.text

        return json.loads(data)

