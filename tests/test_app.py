import pytest
from app import create_app

@pytest.fixture
def app():
    return create_app()

def test_index_redirects_to_login(app):
    client = app.test_client()
    resp = client.get('/', follow_redirects=True)
    assert resp.status_code == 200
    assert '用户登录' in resp.get_data(as_text=True)

def test_login_success_and_dashboard(app):
    client = app.test_client()
    resp = client.post('/login', data={'username':'admin','password':'admin123'}, follow_redirects=True)
    assert resp.status_code == 200
    assert '欢迎，admin' in resp.get_data(as_text=True)

def test_admin_settings_requires_admin(app):
    client = app.test_client()
    resp = client.post('/login', data={'username':'user','password':'user123'}, follow_redirects=True)
    assert resp.status_code == 200
    resp2 = client.get('/admin/settings', follow_redirects=True)
    # 普通用户访问会被重定向到 dashboard
    assert '控制台' in resp2.get_data(as_text=True)
