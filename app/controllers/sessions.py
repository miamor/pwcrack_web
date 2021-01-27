from flask_login import current_user, login_required
from flask import Blueprint, render_template, redirect, url_for, flash, request
from app.lib.base.provider import Provider
import json
import os
import linecache

bp = Blueprint('sessions', __name__)


# https://stackoverflow.com/questions/19574694/flask-hit-decorator-before-before-request-signal-fires
def dont_update_session(func):
    func._dont_update_session = True
    return func


@bp.route('/create', methods=['POST'])
@login_required
def create():
    provider = Provider()
    sessions = provider.sessions()

    description = request.form['description'].strip()
    if len(description) == 0:
        flash('Please enter a session description', 'error')
        return redirect(url_for('home.index'))

    session = sessions.create(current_user.id, description, current_user.username)
    if session is None:
        flash('Could not create session', 'error')
        return redirect(url_for('home.index'))

    return redirect(url_for('sessions.setup_hashes', session_id=session.id))


@bp.route('/<int:session_id>/setup/hashes', methods=['GET'])
@login_required
def setup_hashes(session_id):
    provider = Provider()
    sessions = provider.sessions()
    uploaded_hashes = provider.hashes()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    user_id = 0 if current_user.admin else current_user.id
    session = sessions.get(user_id=user_id, session_id=session_id)[0]

    uploaded_hashfiles = uploaded_hashes.get_uploaded_hashes()

    uploaded_filename_this_session = session.session.filename if session.session.filename else ''

    return render_template(
        'sessions/setup/hashes.html',
        session=session,
        uploaded_hashfiles_json=json.dumps(uploaded_hashfiles, indent=4, sort_keys=True, default=str),
        uploaded_filename_this_session=uploaded_filename_this_session,
    )


@bp.route('/<int:session_id>/setup/hashes/save', methods=['POST'])
@login_required
def setup_hashes_save(session_id):
    provider = Provider()
    sessions = provider.sessions()
    uploaded_hashes = provider.hashes()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    mode = int(request.form['mode'].strip())

    # print('request.files', request.files)

    save_as = ''
    filename = ''
    if mode == 3:
        # Upload encrypted file.
        if len(request.files) < 1:
            flash('Uploaded file could not be found', 'error')
            return redirect(url_for('sessions.setup_hashes', session_id=session_id))

        file = request.files['encryptedfile']
        if file.filename == '':
            flash('No encrypted file uploaded', 'error')
            return redirect(url_for('sessions.setup_hashes', session_id=session_id))

        save_as = sessions.session_filesystem.get_uploadfile_path(current_user.id, session_id, os.path.splitext(file.filename)[1])

        file.save(save_as)
        filename = file.filename

        # run file2john to get hash from file
        hashes = sessions.john_file2hashes(session_id)

        # Enter hashes manually.
        if len(hashes) > 0:
            sessions.session_filesystem.save_hashes(current_user.id, session_id, '\n'.join(hashes))
        else:
            flash('Cannot convert encrypted file to hash', 'error')
            return redirect(url_for('sessions.setup_hashes', session_id=session_id))

    else:
        save_as = sessions.session_filesystem.get_hashfile_path(current_user.id, session_id)

        if mode == 0:
            # Upload hash file.
            if len(request.files) < 1:
                flash('Uploaded file could not be found', 'error')
                return redirect(url_for('sessions.setup_hashes', session_id=session_id))

            file = request.files['hashfile']
            if file.filename == '':
                flash('No hashes uploaded', 'error')
                return redirect(url_for('sessions.setup_hashes', session_id=session_id))

            file.save(save_as)
            filename = file.filename
        elif mode == 1:
            # Enter hashes manually.
            hashes = request.form['hashes'].strip()
            if len(hashes) > 0:
                sessions.session_filesystem.save_hashes(current_user.id, session_id, hashes)
            else:
                flash('No hashes entered', 'error')
                return redirect(url_for('sessions.setup_hashes', session_id=session_id))
        elif mode == 2:
            # Select already uploaded file.
            remotefile = request.form['remotefile'].strip()
            if not uploaded_hashes.is_valid_uploaded_hashfile(remotefile):
                flash('Invalid uploaded file selected', 'error')
                return redirect(url_for('sessions.setup_hashes', session_id=session_id))

            remotefile_location = uploaded_hashes.get_uploaded_hashes_path(remotefile)

            if not uploaded_hashes.copy_file(remotefile_location, save_as):
                flash('Could not copy file', 'error')
                return redirect(url_for('sessions.setup_hashes', session_id=session_id))
        else:
            flash('Invalid mode selected', 'error')
            return redirect(url_for('sessions.setup_hashes', session_id=session_id))

    # update smode in database
    # sessions.set_smode(session_id, mode)
    update_dict = {
        'smode': mode,
        'filename': filename
    }
    sessions.update(session_id, update_dict)

    return redirect(url_for('sessions.setup_node', session_id=session_id))

'''
@bp.route('/<int:session_id>/setup/file2hash', methods=['GET'])
@login_required
def setup_file2hash(session_id):
    provider = Provider()
    john = provider.john()
    sessions = provider.sessions()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    user_id = 0 if current_user.admin else current_user.id
    session = sessions.get(user_id=user_id, session_id=session_id)[0]

    if session.session.smode != 3:
        flash('This step is for [Upload encrypted file] only', 'error')
        return redirect(url_for('sessions.setup_hashes', session_id=session_id))

    hashes = sessions.john_file2hashes(session_id)

    return render_template(
        'sessions/setup/file2hash.html',
        session=session,
        output_john=hashes,
        encrypted_file=session.session.filename,
    )


@bp.route('/<int:session_id>/setup/file2hash/save', methods=['POST'])
@login_required
def setup_file2hash_save(session_id):
    provider = Provider()
    sessions = provider.sessions()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    # run file2john to get hash from file
    file_type = request.form['file_type'] if 'file_type' in request.form else None
    hashes = sessions.john_file2hashes(session_id, file_type)

    # Enter hashes manually.
    if len(hashes) > 0:
        sessions.session_filesystem.save_hashes(current_user.id, session_id, '\n'.join(hashes))
    else:
        flash('Cannot convert encrypted file to hash', 'error')
        return redirect(url_for('sessions.setup_file2hash', session_id=session_id))

    return redirect(url_for('sessions.setup_hashcat', session_id=session_id))
'''

@bp.route('/<int:session_id>/setup/hashcat', methods=['GET'])
@login_required
def setup_hashcat(session_id):
    provider = Provider()
    sessions = provider.sessions()
    hashcat = provider.hashcat()
    system = provider.system()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    user_id = 0 if current_user.admin else current_user.id
    session = sessions.get(user_id=user_id, session_id=session_id)[0]

    supported_hashes = hashcat.get_supported_hashes()
    # We need to process the array in a way to make it easy for JSON usage.
    supported_hashes = hashcat.compact_hashes(supported_hashes)
    if len(supported_hashes) == 0:
        home_directory = system.get_system_user_home_directory()
        flash('Could not get the supported hashes from hashcat', 'error')
        flash('If you have compiled hashcat from source, make sure %s/.hashcat directory exists and is writable' % home_directory, 'error')

    one_hash = ''
    if session.hashfile_exists:
        one_hash = linecache.getline(session.hashfile, 1).strip()

    return render_template(
        'sessions/setup/hashcat.html',
        session=session,
        one_hash=one_hash,
        hashes_json=json.dumps(supported_hashes, indent=4, sort_keys=True, default=str)
    )


@bp.route('/<int:session_id>/setup/hashcat/save', methods=['POST'])
@login_required
def setup_hashcat_save(session_id):
    provider = Provider()
    sessions = provider.sessions()
    hashcat = provider.hashcat()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    hash_type = request.form['hash-type'].strip()
    optimised_kernel = int(request.form.get('optimised_kernel', 0))
    workload = int(request.form.get('workload', 2))
    mode = int(request.form['mode'].strip())

    if mode != 0 and mode != 3:
        # As all the conditions below depend on the mode, if it's wrong return to the previous page immediately.
        flash('Invalid attack mode selected', 'error')
        return redirect(url_for('sessions.setup_hashcat', session_id=session_id))
    elif workload not in [1, 2, 3, 4]:
        flash('Invalid workload selected', 'error')
        return redirect(url_for('sessions.setup_hashcat', session_id=session_id))

    has_errors = False
    if not hashcat.is_valid_hash_type(hash_type):
        has_errors = True
        flash('Invalid hash type selected', 'error')

    if has_errors:
        return redirect(url_for('sessions.setup_hashcat', session_id=session_id))

    sessions.set_hashcat_setting(session_id, 'mode', mode)
    sessions.set_hashcat_setting(session_id, 'hashtype', hash_type)
    sessions.set_hashcat_setting(session_id, 'optimised_kernel', optimised_kernel)
    sessions.set_hashcat_setting(session_id, 'workload', workload)

    redirect_to = 'wordlist' if mode == 0 else 'mask'

    return redirect(url_for('sessions.setup_' + redirect_to, session_id=session_id))


@bp.route('/<int:session_id>/setup/mask', methods=['GET'])
@login_required
def setup_mask(session_id):
    provider = Provider()
    sessions = provider.sessions()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    user_id = 0 if current_user.admin else current_user.id
    session = sessions.get(user_id=user_id, session_id=session_id)[0]

    return render_template(
        'sessions/setup/mask.html',
        session=session
    )


@bp.route('/<int:session_id>/setup/mask/save', methods=['POST'])
@login_required
def setup_mask_save(session_id):
    provider = Provider()
    sessions = provider.sessions()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    mask = request.form['compiled-mask'].strip()
    enable_increments = int(request.form.get('enable_increments', 0))
    if enable_increments == 1:
        increment_min = int(request.form['increment-min'].strip())
        increment_max = int(request.form['increment-max'].strip())
    else:
        increment_min = 0
        increment_max = 0

    has_errors = False
    if len(mask) == 0:
        flash('No mask set', 'error')
        has_errors = True

    if enable_increments == 1:
        if increment_min <= 0:
            has_errors = True
            flash('Min Increment is invalid', 'error')

        if increment_max <= 0:
            has_errors = True
            flash('Max Increment is invalid', 'error')

        if increment_min > increment_max:
            has_errors = True
            flash('Min Increment cannot be bigger than Max Increment', 'error')
    else:
        increment_min = 0
        increment_max = 0

    if has_errors:
        return redirect(url_for('sessions.setup_mask', session_id=session_id))

    sessions.set_hashcat_setting(session_id, 'mask', mask)
    sessions.set_hashcat_setting(session_id, 'increment_min', increment_min)
    sessions.set_hashcat_setting(session_id, 'increment_max', increment_max)

    sessions.sync_mask_to_node(session_id)

    return redirect(url_for('sessions.view', session_id=session_id))


@bp.route('/<int:session_id>/setup/node', methods=['GET'])
@login_required
def setup_node(session_id):
    provider = Provider()
    sessions = provider.sessions()
    nodes = provider.nodes()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    user_id = 0 if current_user.admin else current_user.id
    session = sessions.get(user_id=user_id, session_id=session_id)[0]

    all_nodes = nodes.get(active=1)

    return render_template(
        'sessions/setup/node.html',
        session=session,
        nodes=all_nodes,
    )

@bp.route('/<int:session_id>/setup/node/save', methods=['POST'])
@login_required
def setup_node_save(session_id):
    provider = Provider()
    sessions = provider.sessions()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    node_id = int(request.form['node_id'].strip())

    sessions.set_node(session_id, node_id)

    return redirect(url_for('sessions.settings', session_id=session_id))


@bp.route('/<int:session_id>/setup/wordlist', methods=['GET'])
@login_required
def setup_wordlist(session_id):
    provider = Provider()
    sessions = provider.sessions()
    wordlists = provider.wordlists()
    rules = provider.rules()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    user_id = 0 if current_user.admin else current_user.id
    session = sessions.get(user_id=user_id, session_id=session_id)[0]

    wordlists_node = sessions.get_wordlists_from_node(session_id)
    rules_node = sessions.get_rules_from_node(session_id)

    return render_template(
        'sessions/setup/wordlist.html',
        session=session,
        # wordlists=wordlists.get_wordlists(),
        wordlists_node=wordlists_node,
        # rules=rules.get_rules(),
        rules_node=rules_node
    )


@bp.route('/<int:session_id>/setup/wordlist/save', methods=['POST'])
@login_required
def setup_wordlist_save(session_id):
    provider = Provider()
    sessions = provider.sessions()
    wordlists = provider.wordlists()
    rules = provider.rules()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    wordlist_type = int(request.form['wordlist_type'].strip())

    file = None
    if wordlist_type == 0:
        # Select from Node wordlist.
        wordlist = request.form['wordlist_node'].strip()
        check_local_wordlist_exist = sessions.is_valid_local_wordlist(session_id, wordlist)
        if check_local_wordlist_exist['exist'] is False:
            flash('Invalid wordlist selected', 'error')
            return redirect(url_for('sessions.setup_wordlist', session_id=session_id))

        # wordlist_location = wordlists.get_wordlist_path(wordlist)
        sessions.set_hashcat_setting(session_id, 'wordlist', wordlist)
    elif wordlist_type == 1:
        # Custom wordlist.
        save_as = sessions.session_filesystem.get_custom_wordlist_path(current_user.id, session_id, prefix='custom_wordlist_', random=True)
        if len(request.files) != 1:
            flash('Uploaded file could not be found', 'error')
            return redirect(url_for('sessions.setup_wordlist', session_id=session_id))

        file = request.files['custom_wordlist']
        if file.filename == '':
            flash('No hashes uploaded', 'error')
            return redirect(url_for('sessions.setup_wordlist', session_id=session_id))
        file.filename = save_as.split('/')[-1]
        # file.save(save_as)
        sessions.set_hashcat_setting(session_id, 'wordlist', save_as.split('/')[-1])
    elif wordlist_type == 2:
        # Create wordlist from cracked passwords.
        save_as = sessions.session_filesystem.get_custom_wordlist_path(current_user.id, session_id, prefix='pwd_wordlist')
        sessions.export_cracked_passwords(session_id, save_as)
        sessions.set_hashcat_setting(session_id, 'wordlist', save_as.split('/')[-1])
    else:
        flash('Invalid wordlist option', 'error')
        return redirect(url_for('sessions.setup_wordlist', session_id=session_id))

    sessions.set_hashcat_setting(session_id, 'wordlist_type', wordlist_type)

    rule = request.form['rule'].strip()
    # if len(rule) > 0 and not rules.is_valid_rule(rule):
    if len(rule) > 0:
        check_local_rule_exist = sessions.is_valid_local_rule(session_id, rule)
        if check_local_rule_exist['exist'] is False:
            flash('Invalid rule selected', 'error')
            return redirect(url_for('sessions.setup_wordlist', session_id=session_id))

    # rule_location = rules.get_rule_path(rule)
    sessions.set_hashcat_setting(session_id, 'rule', rule)

    sessions.sync_wordlist_to_node(session_id, custom_wordlist=file)

    return redirect(url_for('sessions.view', session_id=session_id))


@bp.route('/<int:session_id>/view', methods=['GET'])
@login_required
def view(session_id):
    provider = Provider()
    sessions = provider.sessions()
    hashcat = provider.hashcat()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    user_id = 0 if current_user.admin else current_user.id
    session = sessions.get(user_id=user_id, session_id=session_id)[0]

    supported_hashes = hashcat.get_supported_hashes()
    # We need to process the array in a way to make it easy for JSON usage.
    supported_hashes = hashcat.compact_hashes(supported_hashes)

    return render_template(
        'sessions/view.html',
        session=session,
        supported_hashes=supported_hashes
    )


@bp.route('/<int:session_id>/action', methods=['POST'])
@login_required
def action(session_id):
    provider = Provider()
    sessions = provider.sessions()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    user_id = 0 if current_user.admin else current_user.id
    session = sessions.get(user_id=user_id, session_id=session_id)[0]

    if len(session.validation) > 0:
        flash('Please configure all required settings and try again.', 'error')
        return redirect(url_for('sessions.view', session_id=session_id))

    action = request.form['action'].strip()
    result = sessions.hashcat_action(session.session.name, action, session_id)
    if result is False:
        flash('Could not execute action. Please check that all settings have been configured and try again.', 'error')
        return redirect(url_for('sessions.view', session_id=session_id))

    return redirect(url_for('sessions.view', session_id=session_id))


@bp.route('/<int:session_id>/download/<string:which_file>', methods=['POST'])
@login_required
def download_file(session_id, which_file):
    provider = Provider()
    sessions = provider.sessions()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    return sessions.download_file(session_id, which_file)


@bp.route('/<int:session_id>/settings', methods=['GET'])
@login_required
def settings(session_id):
    provider = Provider()
    sessions = provider.sessions()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    user_id = 0 if current_user.admin else current_user.id
    session = sessions.get(user_id=user_id, session_id=session_id)[0]

    return render_template(
        'sessions/settings.html',
        session=session
    )


@bp.route('/<int:session_id>/settings/save', methods=['POST'])
@login_required
def settings_save(session_id):
    provider = Provider()
    sessions = provider.sessions()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    termination_date = request.form['termination_date'].strip()
    termination_time = request.form['termination_time'].strip()
    notifications_enabled = int(request.form.get('notifications_enabled', 0))

    if len(termination_date) == 0:
        flash('Please enter a termination date', 'error')
        return redirect(url_for('sessions.view', session_id=session_id))

    if len(termination_time) == 0:
        # Default to 23:59.
        termination_time = '23:59'

    if not sessions.set_termination_datetime(session_id, termination_date, termination_time):
        flash('Invalid termination date/time entered', 'error')
        return redirect(url_for('sessions.view', session_id=session_id))

    sessions.set_notifications(session_id, notifications_enabled)

    sessions.sync_settings_to_node(session_id)

    flash('Settings saved', 'success')
    return redirect(url_for('sessions.setup_hashcat', session_id=session_id))


@bp.route('/<int:session_id>/history/apply/<int:history_id>', methods=['POST'])
@login_required
def history_apply(session_id, history_id):
    provider = Provider()
    sessions = provider.sessions()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))
    elif not sessions.can_access_history(current_user, session_id, history_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    if not sessions.restore_hashcat_history(session_id, history_id):
        flash('Could not apply historical settings to the current session', 'error')
    else:
        flash('Historical settings applied', 'success')

    return redirect(url_for('sessions.view', session_id=session_id))


@bp.route('/<int:session_id>/status', methods=['GET'])
@dont_update_session
@login_required
def status(session_id):
    provider = Provider()
    sessions = provider.sessions()

    response = {'success': False, 'status': -1}

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return json.dumps(response)

    user_id = 0 if current_user.admin else current_user.id
    session = sessions.get(user_id=user_id, session_id=session_id)[0]
    
    sessions.hashcat_action(session.session.name, 'synchronize_from_node')

    return json.dumps({'result': True, 'status': session.hashcat.state})


@bp.route('/<int:session_id>/files', methods=['GET'])
@login_required
def files(session_id):
    provider = Provider()
    sessions = provider.sessions()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    user_id = 0 if current_user.admin else current_user.id
    session = sessions.get(user_id=user_id, session_id=session_id)[0]
    files = sessions.get_data_files(session.user_id, session_id)

    return render_template(
        'sessions/files.html',
        session=session,
        files=files
    )


@bp.route('/<int:session_id>/active/<string:action>', methods=['POST'])
@login_required
def active_action(session_id, action):
    provider = Provider()
    sessions = provider.sessions()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    if action not in ['show', 'hide']:
        flash('Invalid Action', 'error')
        return redirect(url_for('home.index'))

    active = True if action == 'show' else False
    sessions.set_active(session_id, active)

    flash('Session updated', 'success')
    return redirect(url_for('home.index'))


@bp.route('/<int:session_id>/delete', methods=['POST'])
@login_required
def delete(session_id):
    provider = Provider()
    sessions = provider.sessions()

    if not sessions.can_access(current_user, session_id):
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    if not sessions.delete(session_id):
        flash('Could not delete session', 'error')
        return redirect(url_for('home.index'))

    flash('Session deleted', 'success')
    return redirect(url_for('home.index'))
