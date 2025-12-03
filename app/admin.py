from flask import Blueprint, render_template, request, redirect, url_for
from .auth import role_required
from .models import Setting
from . import db

bp = Blueprint('admin', __name__, url_prefix='/admin')

@bp.route('/')
@role_required('admin')
def index():
    return render_template('admin/index.html', title='后台管理')

@bp.route('/settings', methods=['GET','POST'])
@role_required('admin')
def settings():
    s = Setting.query.first()
    if request.method == 'POST':
        name = request.form.get('app_name')
        logo = request.form.get('logo_url')
        if not s:
            s = Setting(app_name=name, logo_url=logo)
            db.session.add(s)
        else:
            s.app_name = name or s.app_name
            s.logo_url = logo
        db.session.commit()
        return redirect(url_for('admin.settings'))
    return render_template('admin/settings.html', title='系统设置', s=s)

