import collections
import re
from app.utils.node_api import NodeAPI


class HashcatManager:
    def __init__(self, shell, hashcat_binary, status_interval=10, force=False):
        self.shell = shell
        self.hashcat_binary = hashcat_binary
        self.status_interval = 10 if int(status_interval) <= 0 else int(status_interval)
        self.force = force
        self.node_api = None

    def set_nodeapi(self, node):
        self.node_api = NodeAPI(node)

    def get_supported_hashes(self):
        output = self.shell.execute([self.hashcat_binary, '--help'], user_id=0)

        # Split lines using \n and run strip against all elements of the list.
        lines = list(map(str.strip, output.split("\n")))
        hashes = self.__parse_supported_hashes(lines)
        return hashes

    def __parse_supported_hashes(self, lines):
        found = False
        hashes = {}
        for line in lines:
            if line == '- [ Hash modes ] -':
                found = True
            elif found and line == '' and len(hashes) > 0:
                break
            elif found and line != '':
                if line[0] == '#' or line[0] == '=':
                    continue

                # We found a line that has a code/type/description - parse it.
                info = self.__parse_hash_line(line)
                if info is False:
                    continue

                if not info['category'] in hashes:
                    hashes[info['category']] = {}

                hashes[info['category']][info['code']] = info['name']

        return hashes

    def __parse_hash_line(self, line):
        data = list(map(str.strip, line.split('|')))

        if len(data) == 3:
            return {
                'code': data[0],
                'name': data[1],
                'category': data[2]
            }

        return False

    def compact_hashes(self, hashes):
        data = {}
        for type, hashes in hashes.items():
            for code, hash in hashes.items():
                data[code] = type + ' / ' + hash

        # Sort dict - why you gotta be like that python? This is why you have no friends.
        data = collections.OrderedDict(sorted(data.items(), key=lambda kv: kv[1]))
        return data

    def is_valid_hash_type(self, hash_type):
        valid = False
        supported_hashes = self.get_supported_hashes()
        for type, hashes in supported_hashes.items():
            for code, name in hashes.items():
                if code == hash_type:
                    valid = True
                    break

            if valid:
                break

        return valid

    def parse_stream(self, stream):
        stream = str(stream)
        progress = self.__stream_get_last_progress(stream)
        data = self.__convert_stream_progress(progress)

        return data

    def __convert_stream_progress(self, progress):
        data = {}

        progress = progress.split("\n")

        for line in progress:
            parts = line.split(": ", 1)
            if len(parts) != 2:
                continue
            key = parts[0].rstrip(".")
            value = parts[1]

            data[key] = value

        return data

    def __stream_get_last_progress(self, stream):
        # Split all stream by \n.
        # stream = stream.split("\\n")
        stream = stream.split("\n")

        progress_starts_from = self.__stream_find_last_progress_line(stream)
        if progress_starts_from is False:
            return ''

        progress = []
        for i in range(progress_starts_from, len(stream)):
            if stream[i] == '':
                break

            progress.append(stream[i])

        return "\n".join(progress)

    def __stream_find_last_progress_line(self, lines):
        found = False
        for i in range(len(lines) - 1, 0, -1):
            if lines[i].startswith('Session..'):
                found = i
                break

        return found


    def get_process_screen_names(self):
        if self.node_api is None:
            return []
        
        processes = self.get_running_processes_commands()
        names = []

        for process in processes:
            name = self.extract_session_from_process(process)
            if len(name) == 0:
                continue

            names.append(name)

        return names


    def extract_session_from_process(self, process):
        parts = process.split(" ")
        name = ''
        for i, item in enumerate(parts):
            if item == '--session':
                name = parts[i + 1]
                break

        return name

    def is_process_running(self, screen_name):
        screens = self.get_process_screen_names()
        return screen_name in screens

    def __detect_session_status(self, raw, screen_name, tail_screen):
        # States are:
        #   0   NOT_STARTED
        #   1   RUNNING
        #   2   STOPPED
        #   3   FINISHED
        #   4   PAUSED
        #   5   CRACKED
        #   98  ERROR
        #   99  UNKNOWN
        status = 0
        if self.is_process_running(screen_name):
            status = 1
            # If it's still running, there's a chance it's just paused. Check for that.
            if 'Status' in raw:
                if raw['Status'] == 'Paused':
                    status = 4

        # If it's not running, try to get the current status.
        if status == 0:
            if 'Status' in raw:
                if raw['Status'] == 'Running' or raw['Status'] == 'Paused':
                    # If we got to this point it means that the process isn't currently running but there is a 'Status'
                    # feed. In this case, mark it as an error.
                    status = 98
                elif raw['Status'] == 'Quit':
                    status = 2
                elif raw['Status'] == 'Exhausted':
                    status = 3
                elif raw['Status'] == 'Cracked':
                    status = 5

        # In the event that the status is still 0 BUT the screen.log file is not empty, it means there has been some
        # activity, so it's probably an error.
        if status == 0 and len(tail_screen) > 0:
            status = 98

        return status


    def sync_hashcat_status(self, raw, screen_name, tail_screen):
        # Build base dictionary
        data = {
            'process_state': self.__detect_session_status(raw, screen_name, tail_screen),
            'all_passwords': 0,
            'cracked_passwords': 0,
            'time_remaining': '',
            'estimated_completion_time': '',
            'progress': 0
        }

        # progress
        if 'Progress' in raw:
            matches = re.findall('\((\d+.\d+)', raw['Progress'])
            if len(matches) == 1:
                data['progress'] = matches[0]

        # passwords
        if 'Recovered' in raw:
            matches = re.findall('(\d+/\d+)', raw['Recovered'])
            if len(matches) > 0:
                passwords = matches[0].split('/')
                if len(passwords) == 2:
                    data['all_passwords'] = int(passwords[1])
                    data['cracked_passwords'] = int(passwords[0])

        # time remaining
        if 'Time.Estimated' in raw:
            matches = re.findall('\((.*)\)', raw['Time.Estimated'])
            if len(matches) == 1:
                data['time_remaining'] = 'Finished' if matches[0] == '0 secs' else matches[0].strip()

        # estimated completion time
        if 'Time.Estimated' in raw:
            matches = re.findall('(.*)\(', raw['Time.Estimated'])
            if len(matches) == 1:
                data['estimated_completion_time'] = matches[0].strip()

        return data


    def get_running_processes_commands(self):
        if self.node_api is None:
            return None
        return self.node_api.get_running_processes_commands()


    def build_export_password_command_line(self, hashfile, potfile, save_as):
        command = [
            self.hashcat_binary,
            '--potfile-path',
            potfile,
            '--outfile',
            save_as,
            '--outfile-format',
            '2',
            '--show',
            hashfile
        ]

        return command

