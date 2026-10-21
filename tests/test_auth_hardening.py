import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from app import main
from app.login_limits import LoginLimiter

PASSWORD = 'a-long-test-passphrase'


@pytest.fixture
def auth_client(tmp_path, monkeypatch):
    if hasattr(main, 'database'):
        monkeypatch.setattr(main.database, 'DB_PATH', tmp_path / 'auth.sqlite')
    else:
        monkeypatch.setattr(main, 'DATA_DIR', tmp_path)
        monkeypatch.setattr(main, 'DB_PATH', tmp_path / 'auth.sqlite')
    monkeypatch.setattr(main, 'login_limiter', LoginLimiter())
    main.app.dependency_overrides.clear()
    main.initialise()
    client = TestClient(main.app, base_url='https://testserver')
    yield client
    client.close()


def owner(client):
    assert client.post('/api/auth/setup', json={'username': 'owner', 'password': PASSWORD}).status_code == 201


def test_new_password_policy_and_legacy_login(auth_client):
    client = auth_client
    assert client.post('/api/auth/setup', json={'username': 'owner', 'password': 'short'}).status_code == 422
    owner(client)
    for endpoint, body in [('/api/auth/users', {'username': 'new-user', 'password': 'short'}), ('/api/auth/password', {'new_password': 'short'})]:
        assert client.post(endpoint, json=body).status_code == 422
    # Existing passwords keep working until their owner elects to change them.
    salt, hashed = main._new_password('old')
    with main.connect() as db:
        db.execute('UPDATE users SET password_salt=?, password_hash=? WHERE username=?', (salt, hashed, 'owner'))
    client.post('/api/auth/logout')
    assert client.post('/api/auth/login', json={'username': 'owner', 'password': 'old'}).status_code == 200


def test_password_change_revokes_every_existing_session(auth_client):
    client = auth_client
    owner(client)
    second = TestClient(main.app, base_url='https://testserver')
    try:
        assert second.post('/api/auth/login', json={'username': 'owner', 'password': PASSWORD}).status_code == 200
        assert client.post('/api/auth/password', json={'new_password': 'another-long-test-passphrase'}).status_code == 204
        assert client.get('/api/auth/status').json()['user'] is None
        assert second.get('/api/auth/status').json()['user'] is None
        assert client.post('/api/auth/login', json={'username': 'owner', 'password': PASSWORD}).status_code == 401
        assert client.post('/api/auth/login', json={'username': 'owner', 'password': 'another-long-test-passphrase'}).status_code == 200
    finally:
        second.close()


def test_admin_password_reset_revokes_only_target_sessions(auth_client):
    client = auth_client
    owner(client)
    created = client.post('/api/auth/users', json={'username': 'other-user', 'password': PASSWORD}).json()
    second = TestClient(main.app, base_url='https://testserver')
    try:
        assert second.post('/api/auth/login', json={'username': 'other-user', 'password': PASSWORD}).status_code == 200
        assert client.put('/api/auth/users/' + str(created['id']), json={'username': 'other-user', 'password': 'x'}).status_code == 422
        assert client.put('/api/auth/users/' + str(created['id']), json={'username': 'other-user', 'password': 'replacement-long-password'}).status_code == 200
        assert second.get('/api/auth/status').json()['user'] is None
        assert client.get('/api/auth/status').json()['user']['username'] == 'owner'
    finally:
        second.close()


def test_account_throttle_cannot_be_bypassed_with_forwarded_headers(auth_client):
    client = auth_client
    owner(client)
    for number in range(10):
        response = client.post('/api/auth/login', json={'username': 'OWNER' if number % 2 else 'owner', 'password': 'wrong'}, headers={'X-Forwarded-For': f'203.0.113.{number}'})
        assert response.status_code == 401
    response = client.post('/api/auth/login', json={'username': 'owner', 'password': 'wrong'})
    assert response.status_code == 429
    assert 0 < int(response.headers['retry-after']) <= 300
    assert client.get('/api/auth/status').json()['user'] is not None


def test_limiter_expiry_client_limit_and_bounded_memory():
    now = [0]
    limiter = LoginLimiter(clock=lambda: now[0], account_limit=2, client_limit=3, max_keys=4)
    limiter.check('owner', 'client')
    limiter.check('owner', 'client')
    with pytest.raises(HTTPException) as error:
        limiter.check('OWNER', 'different-client')
    assert error.value.status_code == 429
    limiter.succeeded('owner')
    limiter.check('owner', 'client')
    with pytest.raises(HTTPException):
        limiter.check('new-user', 'client')
    now[0] = 301
    limiter.check('owner', 'client')
    limiter.check('second', 'client2')
    with pytest.raises(HTTPException):
        limiter.check('third', 'client3')
    assert len(limiter.attempts) <= 4
