from flask import Blueprint
from flask_login import current_user, login_required
from flask import render_template, redirect, url_for, flash, request
from app.lib.base.provider import Provider


bp = Blueprint('feedbacks', __name__)


@bp.route('/', methods=['GET'])
def index():
    if current_user.admin:
        show_all = 'all' in request.args

        provider = Provider()
        feedbacks = provider.feedbacks()

        all = feedbacks.get(show_all=show_all)

        return render_template(
            'feedbacks/list.html',
            feedbacks=all,
            show_all=show_all
        )
    else:
        return render_template('feedbacks/new.html')


@bp.route('/new', methods=['GET'])
def new():
    return render_template('feedbacks/new.html')

@bp.route('/new/save', methods=['POST'])
def feedback_save():
    # if not current_user.is_authenticated:
    #     return redirect(url_for('auth.login'))

    if 'content' not in request.form or len(request.form['content'].strip()) <= 0:
        flash('Content cannot be empty !','error')
        return redirect(url_for('feedbacks.new'))

    provider = Provider()
    feedbacks = provider.feedbacks()

    content = request.form['content'].strip() if 'content' in request.form else ''
    user_id = current_user.id if current_user.is_authenticated else 0

    if not feedbacks.save(0, user_id, content):
        flash(feedbacks.get_last_error(), 'error')
        return redirect(url_for('feedbacks.new'))

    # return redirect(url_for('home.index'))
    flash('Thanks for your feedback! We\'ll work our best to improve your experience. Have a nice day!', 'success')
    return redirect(url_for('feedbacks.new'))


@bp.route('/<int:feedback_id>/set_processed/<string:action>', methods=['POST'])
@login_required
def set_processed(feedback_id, action):
    if not current_user.admin:
        flash('Permission denied', 'error')
        return redirect(url_for('feedbacks.index'))

    provider = Provider()
    feedbacks = provider.feedbacks()

    if action not in ['processed', 'unprocessed']:
        flash('Invalid Action', 'error')
        return redirect(url_for('feedbacks.index'))

    state = 1 if action == 'processed' else 0
    feedbacks.set_state(feedback_id, state)

    flash('State updated', 'success')
    return redirect(url_for('feedbacks.index'))

