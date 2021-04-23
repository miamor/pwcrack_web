import magic
import os

class John:
    def __init__(self, shell, john_path):
        self.shell = shell
        self.john_path = john_path
    
    def run_file2john(self, filepath, filetype=None):
        office_mimes = [
            'vnd.openxmlformats-officedocument.wordprocessingml.document', #docx
            'vnd.openxmlformats-officedocument.spreadsheetml.sheet', #xlsx
            'vnd.ms-excel.sheet.macroEnabled.12', #xlsm
            'vnd.openxmlformats-officedocument.presentationml.presentation', #pptx
            'msword', #doc
            'excel', 'vnd.ms-excel', 'msexcel', 'x-excel', 'x-msexcel' #xls, xlm
            'powerpoint', 'vnd.ms-powerpoint', 'mspowerpoint', 'x-powerpoint', 'x-mspowerpoint', 
        ]
        rar_mimes = [
            'rar', 'application/x-rar-compressed, application/octet-stream', 'x-rar'
        ]
        zip_mimes = [
            'application/zip, application/octet-stream, application/x-zip-compressed, multipart/x-zip'
        ]

        ftype = ''

        if filetype is None:
            filetype = magic.from_file(filepath, mime=True).split('/')[-1]
        
        if filetype in rar_mimes:
            convert_file = 'rar2john'
            ftype = 'rar'
        elif filetype in zip_mimes:
            convert_file = 'zip2john'
            ftype = 'zip'
        elif filetype == 'pdf':
            convert_file = 'pdf2john.pl'
            ftype = 'pdf'
        elif filetype in office_mimes:
            convert_file = 'office2john.py'
            ftype = 'office'
        elif filetype == 'encrypted':
            ext = os.path.splitext(filepath)[1].split('.')[-1]
            if ext in ['doc', 'dot', 'word', 'docx', 'ppt', 'pptx', 'xla', 'xlb', 'xlc', 'xld', 'xlk', 'xll', 'xlm', 'xls', 'xlt', 'xlv', 'xlw', 'xlsm', 'xlsx', 'pps', 'ppsx']:
                convert_file = 'office2john.py'
                ftype = 'office'
        else:
            return None
        
        
        jbin = convert_file if ftype in ['rar', 'zip'] else os.path.join(self.john_path, convert_file)

        command = [
            jbin,
            filepath
        ]

        output = self.shell.execute(command, user_id=0)

        # Split lines using \n and run strip against all elements of the list.
        lines = list(map(str.strip, output.split("\n")))
        first_dollar = lines[0].find('$')
        strget = lines[0][first_dollar:]
        hash = strget.split(':')[0]

        return hash, ftype
