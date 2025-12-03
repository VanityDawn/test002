from . import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    is_active = db.Column(db.Boolean, default=True)

class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.String(120), default='政企智能舆情分析报告生成智能体应用系统')
    logo_url = db.Column(db.String(255))
