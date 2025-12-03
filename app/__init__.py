from flask import Flask, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import os

db = SQLAlchemy()

def create_app():
    app = Flask(__name__, static_folder='../static', template_folder='../templates')
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'dev'),
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL') or 'sqlite:///app.db',
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    db.init_app(app)

    with app.app_context():
        from .models import User, Setting
        from werkzeug.security import generate_password_hash
        db.create_all()
        if not User.query.first():
            admin = User(username='admin', password_hash=generate_password_hash('admin123'), role='admin')
            user = User(username='user', password_hash=generate_password_hash('user123'), role='user')
            db.session.add_all([admin, user])
            if not Setting.query.first():
                db.session.add(Setting())
            db.session.commit()

    @app.context_processor
    def inject_settings():
        from .models import Setting
        return {'app_settings': Setting.query.first()}

    @app.route('/')
    def index():
        if not session.get('user_id'):
            return redirect(url_for('auth.login'))
        return redirect(url_for('auth.dashboard'))

    from .auth import bp as auth_bp
    app.register_blueprint(auth_bp)
    from .admin import bp as admin_bp
    app.register_blueprint(admin_bp)
    from .api import bp as api_bp
    app.register_blueprint(api_bp)

    return app
