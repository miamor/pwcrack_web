from flask import Blueprint
from flask_login import current_user, login_required
from flask import render_template, redirect, url_for, flash, request
from app.lib.base.provider import Provider


bp = Blueprint('nodes', __name__)


@bp.route('/', methods=['GET'])
def index():
    # This function deliberately doesn't have a @login_required parameter because we want to run a check for a
    # 'first-visit' type scenario, in order to create the administrator.

    provider = Provider()
    users = provider.users()
    if users.get_user_count() == 0:
        # Looks like we need to setup the administrator.
        return redirect(url_for('install.index'))

    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))

    healthcheck = provider.healthcheck()

    errors = healthcheck.run(provider)
    if len(errors) > 0:
        for error in errors:
            flash(error, 'error')

    show_all = 'all' in request.args
    active = None if show_all else True

    nodes = provider.nodes()

    all_nodes = nodes.get()

    return render_template(
        'nodes/index.html',
        nodes=all_nodes,
    )


@bp.route('/new', methods=['GET'])
@login_required
def new():
    return render_template(
        'nodes/new.html',
    )


@bp.route('/create', methods=['POST'])
@login_required
def create():
    provider = Provider()
    nodes = provider.nodes()

    name = request.form['name'].strip()
    hostname = request.form['hostname'].strip()
    port = request.form['port'].strip()
    username = request.form['username'].strip()
    password = request.form['password'].strip()

    hashcat_binary = request.form['hashcat_binary'].strip()
    hashcat_rules_path = request.form['hashcat_rules_path'].strip()
    wordlists_path = request.form['wordlists_path'].strip()
    uploaded_hashes_path = request.form['uploaded_hashes_path'].strip()
    hashcat_status_interval = int(request.form.get('hashcat_status_interval', 10))
    hashcat_force = int(request.form.get('hashcat_force', 0))


    has_errors = False

    if len(name) == 0:
        has_errors = True
        flash('Node name must not be empty', 'error')

    if len(hostname) == 0:
        has_errors = True
        flash('Node hostname must not be empty', 'error')

    if len(port) == 0:
        has_errors = True
        flash('Node port must not be empty', 'error')

    if len(username) == 0:
        has_errors = True
        flash('Node username must not be empty', 'error')

    if len(password) == 0:
        has_errors = True
        flash('Node password must not be empty', 'error')

    if len(hashcat_binary) == 0:
        has_errors = True
        flash('Hashcat executable must not be empty', 'error')

    if len(hashcat_rules_path) == 0:
        has_errors = True
        flash('Hashcat rules directory must not be empty', 'error')

    if len(wordlists_path) == 0:
        has_errors = True
        flash('Wordlist directory must not be empty', 'error')

    if len(uploaded_hashes_path) == 0:
        has_errors = True
        flash('Uploaded Hashes directory must not be empty', 'error')

    if hashcat_status_interval <= 0:
        hashcat_status_interval = 10

    if has_errors:
        return redirect(url_for('nodes.new'))

    res = node_api.update_hashcat_settings(update_dict)
    if res['response'] is False:
        flash(res['msg'], 'error')
        return redirect(url_for('nodes.new'))


    node = nodes.create(name, hostname, port, username, password)
    if node is None:
        flash('Could not create node', 'error')
        return redirect(url_for('nodes.index'))

    return redirect(url_for('nodes.view', node_id=node.id))


@bp.route('/<int:node_id>/view', methods=['GET'])
@login_required
def view(node_id):
    provider = Provider()
    nodes = provider.nodes()
    sessions = provider.sessions()

    node = nodes.get(node_id=node_id)[0]
    sessions_list = sessions.get(node_id=node.node.id)

    node_api = provider.node_api(node)

    rule_files = node_api.get_rules_from_node()
    wordlist_files = node_api.get_wordlists_from_node()

    return render_template(
        'nodes/view.html',
        node=node.node,
        sessions_list=sessions_list,
        rule_files=rule_files,
        wordlist_files=wordlist_files,
    )

@bp.route('/<int:node_id>/update_hashcat/save', methods=['POST'])
@login_required
def update_hashcat_save(node_id):
    provider = Provider()
    nodes = provider.nodes()

    node = nodes.get(node_id=node_id)[0]
    node_api = provider.node_api(node)

    hashcat_binary = request.form['hashcat_binary'].strip()
    hashcat_rules_path = request.form['hashcat_rules_path'].strip()
    wordlists_path = request.form['wordlists_path'].strip()
    uploaded_hashes_path = request.form['uploaded_hashes_path'].strip()
    hashcat_status_interval = int(request.form.get('hashcat_status_interval', 10))
    hashcat_force = int(request.form.get('hashcat_force', 0))


    has_errors = False
    if len(hashcat_binary) == 0:
        has_errors = True
        flash('Hashcat executable must not be empty', 'error')

    if len(hashcat_rules_path) == 0:
        has_errors = True
        flash('Hashcat rules directory must not be empty', 'error')

    if len(wordlists_path) == 0:
        has_errors = True
        flash('Wordlist directory must not be empty', 'error')

    if len(uploaded_hashes_path) == 0:
        has_errors = True
        flash('Uploaded Hashes directory must not be empty', 'error')

    if hashcat_status_interval <= 0:
        hashcat_status_interval = 10

    if has_errors:
        return redirect(url_for('nodes.view', node_id=node_id))


    update_dict = {
        'hashcat_binary': hashcat_binary,
        'hashcat_rules_path': hashcat_rules_path,
        'wordlists_path': wordlists_path,
        'uploaded_hashes_path': uploaded_hashes_path,
        'hashcat_status_interval': hashcat_status_interval,
        'hashcat_force': hashcat_force,
    }

    res = node_api.update_hashcat_settings(update_dict)
    if res['response'] is False:
        flash(res['msg'], 'error')
        return redirect(url_for('nodes.view', node_id=node_id))

    nodes.update(node.id, update_dict)

    return redirect(url_for('nodes.view', node_id=node_id))


@bp.route('/<int:node_id>/active/<string:action>', methods=['POST'])
@login_required
def active_action(node_id, action):
    provider = Provider()
    nodes = provider.nodes()

    # if not sessions.can_access(current_user, node_id):
    #     flash('Access Denied', 'error')
    #     return redirect(url_for('home.index'))

    if action not in ['show', 'hide']:
        flash('Invalid Action', 'error')
        return redirect(url_for('home.index'))

    active = True if action == 'show' else False
    nodes.set_active(node_id, active)

    flash('Session updated', 'success')
    return redirect(url_for('nodes.index'))


