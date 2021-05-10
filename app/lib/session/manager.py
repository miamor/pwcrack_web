import re
import json
import random
import string
import os
import datetime
import time
from app.models.sessions import SessionModel, SessionNotificationModel
from app.models.hashcat import HashcatModel, HashcatHistoryModel
from app.lib.session.filesystem import SessionFileSystem
from app.lib.session.instance import SessionInstance
from app.utils.node_api import NodeAPI
from app.lib.hashcat.instance import HashcatInstance
from app.models.nodes import NodeModel
from app import db
from sqlalchemy import and_, desc
from flask import send_file


class SessionManager:
    def __init__(self, hashcat, john, wordlists, hashid, filesystem, webpush, shell):
        self.hashcat = hashcat
        self.john = john
        self.wordlists = wordlists
        self.hashid = hashid
        self.filesystem = filesystem
        self.webpush = webpush
        self.shell = shell
        self.session_filesystem = SessionFileSystem(filesystem)
        self.cmd_sleep = 2

        self.node_id = 0

    def sanitise_name(self, name):
        return re.sub(r'\W+', '', name)

    def generate_name(self, length=12, prefix=''):
        return prefix + ''.join(random.choice(string.ascii_letters + string.digits) for i in range(length))

    def __generate_screen_name(self, user_id, name):
        return str(user_id) + '_' + name

    def exists(self, user_id, name, active=True):
        return self.__get(user_id, name, active) is not None

    def __get(self, user_id, name, active):
        return SessionModel.query.filter(
            and_(
                SessionModel.user_id == user_id,
                SessionModel.name == name,
                SessionModel.active == active
            )
        ).first()

    def __get_by_id(self, session_id):
        return SessionModel.query.filter(SessionModel.id == session_id).first()

    def get_by_nodeid(self, node_id):
        return SessionModel.query.filter(SessionModel.node_id == node_id).all()

    def create(self, user_id, description, prefix, is_admin):
        prefix = self.sanitise_name(prefix) + '_'
        name = self.generate_name(prefix=prefix, length=4)

        # If it exists (shouldn't), return it.
        session = self.__get(user_id, name, True)
        if session:
            return session
        
        claim = True if is_admin else False

        session = SessionModel(
            user_id=user_id,
            name=name,
            description=description,
            active=True,
            screen_name='',
            claim=claim
        )
        db.session.add(session)
        db.session.commit()
        # In order to get the created object, we need to refresh it.
        db.session.refresh(session)

        # We need to append the session_id to the session name.
        name = name + '_' + str(session.id)
        session.name = name
        session.screen_name = self.__generate_screen_name(user_id, name)

        db.session.commit()
        # In order to get the created object, we need to refresh it.
        db.session.refresh(session)

        return session

    def can_access(self, user, session_id):
        if user.admin:
            return True

        session = SessionModel.query.filter(
            and_(
                SessionModel.user_id == user.id,
                SessionModel.id == session_id
            )
        ).first()

        return True if session else False

    def can_access_history(self, user, session_id, history_id):
        if user.admin:
            return True

        history = HashcatHistoryModel.query.filter(
            and_(
                HashcatHistoryModel.id == history_id,
                HashcatHistoryModel.session_id == session_id
            )
        ).first()

        return True if history else False

    def get(self, user_id=0, session_id=0, node_id=0, active=None):
        query = SessionModel.query
        if user_id > 0:
            query = query.filter(SessionModel.user_id == user_id)

        if session_id > 0:
            query = query.filter(SessionModel.id == session_id)

        if node_id > 0:
            query = query.filter(SessionModel.node_id == node_id)

        if active is not None:
            query = query.filter(SessionModel.active == active)

        sessions = query.order_by(SessionModel.created_at.desc()).all()

        data = []
        for session in sessions:
            node = NodeModel.query.filter(NodeModel.id == session.node_id).first()
            hashcat_instance = HashcatInstance(session, node, self.session_filesystem, self.hashcat, self.wordlists)
            # instance = SessionInstance(session, node, hashcat_instance, self.session_filesystem, self.hashid)
            instance = SessionInstance(session, hashcat_instance, self.session_filesystem, self.hashid)
            data.append(instance)

        return data
    

    def session_sync_hashcat_status(self, session):
        hashcat_instance = session.hashcat
        data = hashcat_instance.hashcat.sync_hashcat_status(hashcat_instance.hashcat_data_raw, session.screen_name, hashcat_instance.tail_screen)
        
        hashcat_instance.settings.data = json.dumps(data)

        db.session.commit()
        db.session.refresh(hashcat_instance.settings)
        return True
    

    def session_sync_hashcat_status_all(self):
        sessions = SessionModel.query.order_by(SessionModel.created_at.desc()).all()

        data = []
        for session in sessions:
            node = NodeModel.query.filter(NodeModel.id == session.node_id).first()
            hashcat_instance = HashcatInstance(session, node, self.session_filesystem, self.hashcat, self.wordlists)

            # print('hashcat_instance.settings', hashcat_instance.settings)

            if hashcat_instance.settings is not None:
                data = json.dumps(hashcat_instance.hashcat.sync_hashcat_status(hashcat_instance.hashcat_data_raw, session.screen_name, hashcat_instance.tail_screen))
            
                hashcat_instance.settings.data = data

                db.session.commit()
                db.session.refresh(hashcat_instance.settings)
        
        return True


    def restore_hashcat_history(self, session_id, history_id):
        history = HashcatHistoryModel.query.filter(HashcatHistoryModel.id == history_id).first()
        current = HashcatModel.query.filter(HashcatModel.session_id == session_id).first()

        if not history or not current:
            return False

        current.mode = history.mode
        current.hashtype = history.hashtype
        current.wordlist_type = history.wordlist_type
        current.wordlist = history.wordlist
        current.rule = history.rule
        current.mask = history.mask
        current.increment_min = history.increment_min
        current.increment_max = history.increment_max
        current.optimised_kernel = history.optimised_kernel
        current.workload = history.workload

        db.session.commit()
        return True

    def set_hashcat_setting(self, session_id, name, value):
        record = self.get_hashcat_settings(session_id)
        if not record:
            record = self.__create_hashcat_record(session_id)

        if name == 'mode':
            record.mode = value
        elif name == 'hashtype':
            record.hashtype = value
        elif name == 'wordlist':
            record.wordlist = value
        elif name == 'rule':
            record.rule = value
        elif name == 'mask':
            record.mask = value
        elif name == 'increment_min':
            record.increment_min = value
        elif name == 'increment_max':
            record.increment_max = value
        elif name == 'optimised_kernel':
            record.optimised_kernel = value
        elif name == 'wordlist_type':
            record.wordlist_type = value
        elif name == 'workload':
            record.workload = value

        db.session.commit()

    def get_hashcat_settings(self, session_id):
        return HashcatModel.query.filter(HashcatModel.session_id == session_id).first()

    def __create_hashcat_record(self, session_id):
        record = HashcatModel(
            session_id=session_id
        )

        db.session.add(record)
        db.session.commit()
        # In order to get the created object, we need to refresh it.
        db.session.refresh(record)

        return record

    def export_cracked_passwords(self, session_id, save_as):
        # First get the session.
        session = self.get(session_id=session_id)[0]

        command = self.hashcat.build_export_password_command_line(
            self.session_filesystem.get_hashfile_path(session.user_id, session_id),
            self.session_filesystem.get_potfile_path(session.user_id, session_id),
            save_as
        )
        out = self.shell.execute(command)
        # print('~~~~[export_cracked_passwords] out', out)

        return True
    
    def set_node(self, session_id, node_id):
        self.node_id = node_id

        # update smode in database
        # sessions.set_smode(session_id, mode)
        update_dict = {
            'node_id': node_id
        }
        self.update(session_id, update_dict)


        # First get the session.
        session = self.get(session_id=session_id)[0]

        session_record = session.session

        user_data_path = self.session_filesystem.get_user_data_path(session.session.user_id, session_id)

        if self.hashcat.node_api is None:
            self.hashcat.node_api = NodeAPI(session.hashcat.node)

        # send data to local node
        payload = {
            'session_record': {
                'id': session.session.id,
                'user_id': session.session.user_id,
                'name': session.session.name,
                'description': session.session.description,
                'smode': session.session.smode,
                'filename': session.session.filename,
                'screen_name': session.session.screen_name,
                'active': session.session.active,
                'hints': session.hints,
                # 'terminate_at': str(session.session.terminate_at),
                # 'created_at': str(session.session.created_at)
            },
            'user_data_path': user_data_path,
        }
                
        hashfile_path = self.session_filesystem.get_hashfile_path(session.user_id, session_id)

        return self.hashcat.node_api.create_hashcat_session(payload, filepaths=[hashfile_path])


    def is_valid_local_wordlist(self, session_id, wordlist):
        if self.hashcat.node_api is None:
            # First get the session.
            session = self.get(session_id=session_id)[0]
            self.hashcat.node_api = NodeAPI(session.hashcat.node)
        return self.hashcat.node_api.is_valid_local_wordlist(wordlist)
    
    def is_valid_local_rule(self, session_id, rule):
        if self.hashcat.node_api is None:
            # First get the session.
            session = self.get(session_id=session_id)[0]
            self.hashcat.node_api = NodeAPI(session.hashcat.node)
        return self.hashcat.node_api.is_valid_local_rule(rule)

    def sync_wordlist_to_node(self, session_id, custom_wordlist=None):
        # First get the session.
        session = self.get(session_id=session_id)[0]

        hashcat_record = session.hashcat.settings

        user_data_path = self.session_filesystem.get_user_data_path(session.session.user_id, session_id)

        if self.hashcat.node_api is None:
            self.hashcat.node_api = NodeAPI(session.hashcat.node)

        # send data to local node
        payload = {
            'session_record': {
                'id': session.session.id,
                'user_id': session.session.user_id,
                'hints': session.hints,
            },
            'hashcat_record': {
                'id': session.hashcat.settings.id,
                'session_id': session.hashcat.settings.session_id,
                'mode': session.hashcat.settings.mode,
                'workload': session.hashcat.settings.workload,
                'hashtype': session.hashcat.settings.hashtype,
                'wordlist_type': session.hashcat.settings.wordlist_type,
                'wordlist': session.hashcat.settings.wordlist,
                'rule': session.hashcat.settings.rule,
                'mask': session.hashcat.settings.mask,
                'increment_min': session.hashcat.settings.increment_min,
                'increment_max': session.hashcat.settings.increment_max,
                'optimised_kernel': session.hashcat.settings.optimised_kernel,
                'created_at': str(session.hashcat.settings.created_at)
            },
            'user_data_path': user_data_path,
        }
                

        filepaths = []

        if hashcat_record.wordlist_type == 1 and custom_wordlist is not None:
            return self.hashcat.node_api.sync_hashcat_session(payload, filepaths=[], files=[custom_wordlist])

        elif hashcat_record.wordlist_type == 2:
            for filename in os.listdir(user_data_path):
                if 'custom_wordlist' in filename or 'pwd_wordlist' in filename:
                    filepaths.append(user_data_path+'/'+filename)

        return self.hashcat.node_api.sync_hashcat_session(payload, filepaths=filepaths)


    def sync_mask_to_node(self, session_id):
        # First get the session.
        session = self.get(session_id=session_id)[0]

        hashcat_record = session.hashcat.settings

        user_data_path = self.session_filesystem.get_user_data_path(session.session.user_id, session_id)

        if self.hashcat.node_api is None:
            self.hashcat.node_api = NodeAPI(session.hashcat.node)

        # send data to local node
        payload = {
            'session_record': {
                'id': session.session.id,
                'user_id': session.session.user_id,
                'hints': session.hints,
            },
            'hashcat_record': {
                'id': session.hashcat.settings.id,
                'session_id': session.hashcat.settings.session_id,
                'mode': session.hashcat.settings.mode,
                'workload': session.hashcat.settings.workload,
                'hashtype': session.hashcat.settings.hashtype,
                'wordlist_type': session.hashcat.settings.wordlist_type,
                'wordlist': session.hashcat.settings.wordlist,
                'rule': session.hashcat.settings.rule,
                'mask': session.hashcat.settings.mask,
                'increment_min': session.hashcat.settings.increment_min,
                'increment_max': session.hashcat.settings.increment_max,
                'optimised_kernel': session.hashcat.settings.optimised_kernel,
                'created_at': str(session.hashcat.settings.created_at)
            },
            'user_data_path': user_data_path,
        }
        
        return self.hashcat.node_api.sync_hashcat_session(payload, filepaths=[])


    def sync_settings_to_node(self, session_id):
        # First get the session.
        session = self.get(session_id=session_id)[0]

        session_record = session.session

        if self.hashcat.node_api is None:
            self.hashcat.node_api = NodeAPI(session.hashcat.node)

        # send data to local node
        payload = {
            'session_record': {
                'id': session.session.id,
                'user_id': session.session.user_id,
                'terminate_at': str(session.session.terminate_at),
                'hints': session.hints
            },
        }
        
        return self.hashcat.node_api.sync_session(payload)
    
    def get_wordlists_from_node(self, session_id):
        if self.hashcat.node_api is None:
            # First get the session.
            session = self.get(session_id=session_id)[0]
            self.hashcat.node_api = NodeAPI(session.hashcat.node)
        return self.hashcat.node_api.get_wordlists_from_node()

    def get_rules_from_node(self, session_id):
        if self.hashcat.node_api is None:
            # First get the session.
            session = self.get(session_id=session_id)[0]
            self.hashcat.node_api = NodeAPI(session.hashcat.node)
        return self.hashcat.node_api.get_rules_from_node()


    def hashcat_action(self, session, action, session_id=0):
        print('session', session)
        session_name = session.session.name
        if action == 'synchronize_from_node':
            self.session_sync_hashcat_status(session)
        elif action == 'start' and session_id > 0:
            # Every time we start a session, we make a copy of the settings and put them in the hashcat_history table.
            self.__save_hashcat_history(session_id)
            self.session_sync_hashcat_status(session)
        resp = self.hashcat.node_api.hashcat_action(session_name, action)
        return resp

    def john_file2hashes(self, session_id, filetype=None):
        # First get the session.
        session = self.get(session_id=session_id)[0]

        # print('~~~~~~~~ os.path.splitext(session.session.filename)[1]', os.path.splitext(session.session.filename)[1])

        encrypted_file = self.session_filesystem.get_uploadfile_path(session.user_id, session_id, os.path.splitext(session.session.filename)[1])

        output_john, _ = self.john.run_file2john(encrypted_file, filetype)
        hashes = [output_john]
        return hashes
    
    def __save_hashcat_history(self, session_id):
        record = HashcatModel.query.filter(HashcatModel.session_id == session_id).first()
        new_record = HashcatHistoryModel(
            session_id=record.session_id,
            mode=record.mode,
            hashtype=record.hashtype,
            wordlist=record.wordlist,
            wordlist_type=record.wordlist_type,
            rule=record.rule,
            mask=record.mask,
            increment_min=record.increment_min,
            increment_max=record.increment_max,
            optimised_kernel=record.optimised_kernel,
            workload=record.workload,
            created_at=datetime.datetime.now(),
        )

        db.session.add(new_record)
        db.session.commit()
        # In order to get the created object, we need to refresh it.
        db.session.refresh(new_record)
        return True

    def get_hashcat_status(self, user_id, session_id):
        screen_log_file = self.session_filesystem.find_latest_screenlog(user_id, session_id)
        stream = self.session_filesystem.tail_file(screen_log_file, 4096)
        if len(stream) == 0:
            return {}

        # Pass to hashcat class to parse and return a dict with all the data.
        data = self.hashcat.parse_stream(stream)

        return data

    def download_file(self, session_id, which_file):
        session = self.get(session_id=session_id)[0]

        save_as = session.description
        if which_file == 'cracked':
            file = self.session_filesystem.get_crackedfile_path(session.user_id, session_id)
            save_as = save_as + '.cracked.txt'
        elif which_file == 'encrypt':
            file = self.session_filesystem.find_uploadfile_path(session.user_id, session_id)
            ext = os.path.splitext(file)[1] if file is not None else ''
            save_as = save_as + '.original_encrypted_file'+ext
        elif which_file == 'hashes' or which_file == 'all':
            file = self.session_filesystem.get_hashfile_path(session.user_id, session_id)
            save_as = save_as + '.hashes.txt'
        elif which_file == 'plain':
            file = self.session_filesystem.get_custom_wordlist_path(session.user_id, session_id, prefix='pwd_wordlist')
            self.export_cracked_passwords(session_id, file)
            save_as = save_as + '.plain.txt'
        else:
            # It means it's a raw/screen log file.
            files = self.get_data_files(session.user_id, session_id)
            if not which_file in files:
                return 'Error'
            file = files[which_file]['path']
            save_as = which_file

        if file is None or not os.path.exists(file):
            return 'Error'

        return send_file(file, attachment_filename=save_as, as_attachment=True)

    def get_running_processes(self):
        return self.hashcat.node_api.get_running_processes()

    def set_termination_datetime(self, session_id, date, time):
        date_string = date + ' ' + time

        # Check if the format is valid.
        try:
            fulldate = datetime.datetime.strptime(date_string, '%Y-%m-%d %H:%M')
        except ValueError:
            return False

        if self.__is_past_date(fulldate):
            return False

        session = self.__get_by_id(session_id)
        session.terminate_at = fulldate
        db.session.commit()
        # In order to get the created object, we need to refresh it.
        db.session.refresh(session)

        return True

    def __is_past_date(self, date):
        return datetime.datetime.now() > date

    def terminate_past_sessions(self):
        # Get all sessions which have terminate_at set as a past datetime.
        print("Trying to get past sessions...")
        past_sessions = SessionModel.query.filter(SessionModel.terminate_at < datetime.datetime.now()).all()
        for past_session in past_sessions:
            # Check if session is currently running.
            print("Loading session %d" % past_session.id)
            session = self.get(past_session.user_id, past_session.id)
            if len(session) == 0:
                print("Session %d does not exist" % past_session.id)
                continue
            print("Session %d loaded" % past_session.id)
            session = session[0]

            status = session.hashcat.state
            if status == 1 or status == 4:
                # If it's running or paused, terminate.
                print("Terminating session %d" % past_session.id)
                self.hashcat_action(session, 'stop', session.id)

    def get_data_files(self, user_id, session_id):
        user_data_path = self.session_filesystem.get_user_data_path(user_id, session_id)
        return self.filesystem.get_files(user_data_path)

    def set_notifications(self, session_id, enabled):
        session = self.__get_by_id(session_id)
        session.notifications_enabled = enabled

        db.session.commit()

        return True

    def send_notifications(self):
        # Get all sessions with enabled notifications.
        print("Loading sessions with notifications enabled.")
        sessions = SessionModel.query.filter(
            and_(
                SessionModel.active == 1,
                SessionModel.notifications_enabled == 1
            )
        ).all()

        if not sessions or len(sessions) == 0:
            print("No sessions loaded")
            return True

        print("Loaded %d sessions" % len(sessions))
        for session in sessions:
            full_session = self.get(session_id=session.id)[0]
            if not full_session:
                print("Could not get the actual session's details")
                continue

            # Get the currently cracked passwords.
            all_passwords = int(full_session.hashcat.all_passwords)
            cracked = int(full_session.hashcat.cracked_passwords)

            # Get the last sent notification.
            sent = SessionNotificationModel.query.filter(
                SessionNotificationModel.session_id == session.id
            ).order_by(
                desc(SessionNotificationModel.id)
            ).first()
            previously_cracked = sent.cracked if sent else 0

            # Check if the currently cracked passwords are more than the ones previously sent.
            if previously_cracked >= cracked:
                print("Skipping notification - cracked are less or equal than previously cracked")
                continue

            # Send notification.
            title = 'Progress Update'
            body = '%d/%d Hashes Recovered' % (cracked, all_passwords)
            url = '/sessions/%d/view' % session.id

            print("Sending notification to user %d for session %d" % (full_session.user_id, session.id))
            if self.webpush.send(session.user_id, title, body, url):
                print("Notification sent")
                # Save current notification
                log = SessionNotificationModel(
                    session_id=session.id,
                    cracked=cracked,
                    sent_at=datetime.datetime.now()
                )

                db.session.add(log)
                db.session.commit()
            else:
                print("Could not send notification")

        print("Finished sending notifications")
        return True

    def set_active(self, session_id, active):
        session = self.__get_by_id(session_id)
        session.active = active

        db.session.commit()
        db.session.refresh(session)
        return True

    def set_smode(self, session_id, smode=0):
        session = self.__get_by_id(session_id)
        session.smode = smode

        db.session.commit()
        db.session.refresh(session)
        return True

    def update(self, session_id, update_dict):
        session = self.__get_by_id(session_id)

        for key in list(update_dict.keys()):
            val = update_dict[key]
            if key == 'smode':
                session.smode = val
            elif key == 'filename':
                session.filename = val
            elif key == 'node_id':
                session.node_id = val
            elif key == 'hints':
                session.hints = val
            elif key == 'claim':
                session.claim = val

        db.session.commit()
        db.session.refresh(session)
        return True

    def delete(self, session_id):
        session = self.get(session_id=session_id)
        if not session or len(session) == 0:
            # If we can't get the session, consider it deleted - MIND GAMES!
            return True

        session = session[0]
        if session.hashcat.state in [1, 4]:
            # Session is either running or paused.
            return False

        # Delete data first.
        data_path = self.session_filesystem.get_user_data_path(session.user_id, session.id)
        if os.path.isdir(data_path):
            self.session_filesystem.delete_path(data_path)

        # Now delete database records.
        HashcatModel.query.filter_by(session_id=session.id).delete()
        HashcatHistoryModel.query.filter_by(session_id=session.id).delete()
        SessionNotificationModel.query.filter_by(session_id=session.id).delete()
        SessionModel.query.filter_by(id=session.id).delete()

        db.session.commit()
        return True
