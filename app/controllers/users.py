from flask import Blueprint
from flask_login import current_user, login_required
from flask import render_template, redirect, url_for, flash, request
from app.lib.base.provider import Provider


bp = Blueprint('users', __name__)


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

    users = provider.users()

    all_users = users.get()

    return render_template(
        'users/index.html',
        users=all_users,
    )


@bp.route('/new', methods=['GET'])
@login_required
def new():
    if not current_user.admin:
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    provider = Provider()
    departments = provider.departments()
    depts = departments.get()
    
    return render_template(
        'users/edit.html',
        user=None, depts=depts
    )



@bp.route('/<int:user_id>/view', methods=['GET'])
@login_required
def view(user_id):
    provider = Provider()
    users = provider.users()

    user = users.get(user_id=user_id)[0]

    return render_template(
            'users/view.html',
            user=user,
        )




@bp.route('/<int:user_id>/edit', methods=['GET'])
@login_required
def edit(user_id):
    if not current_user.admin:
        flash('Access Denied', 'error')
        return redirect(url_for('users.view', user_id=user_id))

    provider = Provider()
    users = provider.users()
    departments = provider.departments()
    depts = departments.get()

    user = None if user_id <= 0 else users.get_by_id(user_id)

    return render_template(
        'users/edit.html',
        user=user, depts=depts
    )


@bp.route('/<int:user_id>/edit/save', methods=['POST'])
@login_required
def edit_save(user_id):
    if not current_user.admin:
        flash('Access Denied', 'error')
        return redirect(url_for('users.view', user_id=user_id))

    username = request.form['username'].strip() if 'username' in request.form else ''
    password = request.form['password'].strip() if 'password' in request.form else ''
    full_name = request.form['full_name'].strip() if 'full_name' in request.form else ''
    email = request.form['email'].strip() if 'email' in request.form else ''
    phone = request.form['phone'].strip() if 'phone' in request.form else ''
    phong = request.form['phong'].strip() if 'phong' in request.form else ''
    chucvu = request.form['chucvu'].strip() if 'chucvu' in request.form else ''
    admin = int(request.form.get('admin', 0))
    ldap = int(request.form.get('ldap', 0))
    active = int(request.form.get('active', 0))

    provider = Provider()
    users = provider.users()

    if not users.save(user_id, username, password, full_name, email, phone, phong, chucvu, admin, ldap, active):
        flash(users.get_last_error(), 'error')
        return redirect(url_for('users.edit', user_id=user_id))

    flash('User saved', 'success')
    return redirect(url_for('users.index'))




@bp.route('/<int:user_id>/active/<string:action>', methods=['POST'])
@login_required
def active_action(user_id, action):
    if not current_user.admin:
        flash('Access Denied', 'error')
        return redirect(url_for('users.index'))

    provider = Provider()
    users = provider.users()

    # if not sessions.can_access(current_user, node_id):
    #     flash('Access Denied', 'error')
    #     return redirect(url_for('home.index'))

    if action not in ['show', 'hide']:
        flash('Invalid Action', 'error')
        return redirect(url_for('home.index'))

    active = True if action == 'show' else False
    users.set_active(user_id, active)

    flash('User updated', 'success')
    return redirect(url_for('users.index'))



