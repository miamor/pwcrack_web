from flask_login import current_user, login_required
from flask import Blueprint, render_template, redirect, url_for, flash, request
from app.lib.base.provider import Provider
import json
import os
import linecache
from werkzeug.utils import secure_filename

bp = Blueprint('utils', __name__)


@bp.route('/file2hash', methods=['GET'])
@login_required
def file2hash():
    provider = Provider()

    user_id = 0 if current_user.admin else current_user.id

    return render_template(
        'utils/file2hash.html'
    )


@bp.route('/file2hash/gethash', methods=['POST'])
@login_required
def file2hash_gethash():
    provider = Provider()
    john = provider.john()

    hash_val = None

    # run file2john to get hash from file
    enc_file = request.files.getlist('file')[0]
    # for enc_file in files:
    filename = secure_filename(enc_file.filename.encode("ascii", "ignore").decode())
    save_as = '/tmp/'+filename
    enc_file.save(save_as)
    if os.path.exists(save_as):
        hash_val, filetype = john.run_file2john(save_as)
    # file_type = request.form['file_type'] if 'file_type' in request.form else None
    # output_john = john.run_file2john(enc_file, file_type)
    # hashes.append(output_john)

    # Enter hashes manually.
    if hash_val is None:
        return {'status': 'error', 'msg': 'Cannot convert encrypted file to hash'}

    return {'status': 'success', 'hash': hash_val, 'type': filetype}
