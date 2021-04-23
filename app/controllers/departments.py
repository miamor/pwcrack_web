from flask import Blueprint
from flask_login import current_user, login_required
from flask import render_template, redirect, url_for, flash, request
from app.lib.base.provider import Provider


bp = Blueprint('departments', __name__)


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

    departments = provider.departments()

    all_departments = departments.get()

    return render_template(
        'departments/index.html',
        departments=all_departments,
    )

@bp.route('/new', methods=['GET'])
@login_required
def new():
    if not current_user.admin:
        flash('Access Denied', 'error')
        return redirect(url_for('home.index'))

    return render_template(
        'departments/edit.html',
        dept=None
    )

@bp.route('/<dep_id>/view', methods=['GET'])
@login_required
def view(dep_id):
    provider = Provider()
    departments = provider.departments()
    dept = departments.get(dep_id)[0]

    return render_template(
            'departments/view.html',
            dept=dept,
        )

@bp.route('/<dep_id>/edit', methods=['GET'])
@login_required
def edit(dep_id):
    if not current_user.admin:
        flash('Access Denied', 'error')
        return redirect(url_for('departments.view', dep_id=dep_id))

    provider = Provider()
    departments = provider.departments()

    dept = None if dep_id == '0' else departments.get_by_id(dep_id)

    return render_template(
        'departments/edit.html',
        dept=dept
    )

@bp.route('/<dep_id>/edit/save', methods=['POST'])
@login_required
def edit_save(dep_id):
    if not current_user.admin:
        flash('Access Denied', 'error')
        return redirect(url_for('departments.view', dep_id=dep_id))

    name = request.form['name'].strip() if 'name' in request.form else ''
    color = request.form['color'].strip() if 'color' in request.form else ''

    provider = Provider()
    departments = provider.departments()

    if not departments.save(dep_id, name, color):
        flash(departments.get_last_error(), 'error')
        return redirect(url_for('departments.edit', dep_id=dep_id))

    flash('User saved', 'success')
    return redirect(url_for('departments.index'))

