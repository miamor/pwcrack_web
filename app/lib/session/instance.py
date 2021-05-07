import os
from app.lib.models.department import DepartmentModel
from app.lib.models.user import UserModel
from app.lib.models.hashcat import HashcatHistoryModel
from sqlalchemy import desc
import linecache

class SessionInstance:
    def __init__(self, session, hashcat, filesystem, hashid):
        self.session = session
        self.hashcat = hashcat
        self.filesystem = filesystem
        self.hashid = hashid
        self.user = UserModel.query.filter(UserModel.id == session.user_id).first()
        self.user_dept = DepartmentModel.query.filter(DepartmentModel.id == self.user.phong).first()

        self._hashes_in_file = None
        self._hashfile = None

        self._top_prio_hashtype = {
            400: 'phpass, WordPress (MD5), Joomla (MD5), phpBB3 (MD5)',
            1000: 'NTLM',
            9400: 'MS Office 2007',
            9500: 'MS Office 2010',
            9600: 'MS Office 2013',
            9700: 'MS Office ⇐ 2003 MD5 + RC4, oldoffice$0, oldoffice$1',
            9710: 'MS Office ⇐ 2003 $0/$1, MD5 + RC4, collider #1',
            9720: 'MS Office ⇐ 2003 $0/$1, MD5 + RC4, collider #2',
            9800: 'MS Office ⇐ 2003 SHA1 + RC4, oldoffice$3, oldoffice$4',
            9810: 'MS Office ⇐ 2003 $3, SHA1 + RC4, collider #1',
            9820: 'MS Office ⇐ 2003 $3, SHA1 + RC4, collider #2',
            10400: 'PDF 1.1 - 1.3 (Acrobat 2 - 4)',
            10410: 'PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #1',
            10420: 'PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #2',
            10500: 'PDF 1.4 - 1.6 (Acrobat 5 - 8)',
            10600: 'PDF 1.7 Level 3 (Acrobat 9)',
            10700: 'PDF 1.7 Level 8 (Acrobat 10 - 11)',
            111: 'nsldaps, SSHA-1(Base64), Netscape LDAP SSHA',
            1411: 'SSHA-256(Base64), LDAP {SSHA256}',
            1711: 'SSHA-512(Base64), LDAP {SSHA512}',
            0: 'MD5',
            100: 'SHA1',
        }

    @property
    def id(self):
        return self.session.id

    @property
    def description(self):
        return self.session.description

    @property
    def name(self):
        return self.session.name

    @property
    def username(self):
        return self.user.username
    
    @property
    def node_id(self):
        return self.session.node_id

    @property
    def terminate_at(self):
        return self.session.terminate_at

    @property
    def user_id(self):
        return self.session.user_id

    @property
    def hints(self):
        return self.session.hints

    @property
    def claim(self):
        return self.session.claim

    @property
    def reclaim(self):
        return self.session.reclaim

    @property
    def screen_name(self):
        return self.session.screen_name

    @property
    def active(self):
        return self.session.active

    @property
    def notifications_enabled(self):
        return self.session.notifications_enabled

    @property
    def created_at(self):
        return self.session.created_at

    @property
    def friendly_name(self):
        return self.session.description if len(self.session.description) > 0 else self.session.name

    @property
    def hashfile(self):
        if self._hashfile is None:
            self._hashfile = self.filesystem.get_hashfile_path(self.session.user_id, self.session.id)
        return self._hashfile

    @property
    def hashes_in_file(self):
        if self._hashes_in_file is None:
            self._hashes_in_file = self.filesystem.count_non_empty_lines_in_file(self.hashfile)
        return self._hashes_in_file

    @property
    def hashfile_exists(self):
        return os.path.isfile(self.hashfile)

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
            HashcatHistoryModel.session_id == self.id
        ).order_by(desc(HashcatHistoryModel.id)).all()

    @property
    def guess_hashtype(self):
        if not self.hashfile_exists:
            return []

        try:
            # with open(self.hashfile, 'r') as f:
            #     hash = f.readline().strip()
            hash = linecache.getline(self.hashfile, 1).strip()
        except UnicodeDecodeError:
            hash = ''
        
        # print('hash', hash)

        return self.hashid.guess(hash)

    @property
    def selected_hashtype(self):
        if len(self.guess_hashtype[0]) == 0:
            return 0
        
        for top_prio in list(self._top_prio_hashtype.keys()):
            # for hashtype in self.guess_hashtype:
            #     print('hashtype', hashtype)
            #     if hashtype[1] == top_prio:
            #         return hashtype

            if self.hashcat.hashtype:
                return self.hashcat.hashtype
            
            print('self.guess_hashtype', self.guess_hashtype)
            if len(self.guess_hashtype) == 0:
                return ''
            
            if top_prio in self.guess_hashtype[1]: # in hashtype codes
                return top_prio
                
        return self.guess_hashtype[1][0]