from flask import Flask, request
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import io
from util import *
from datetime import datetime
import authbot as bot
import threading
import math
from base64 import b64decode, b64encode

NAME = 'name'
INTERVAL = 30
DEBUG = True
app = Flask(__name__)
auth = HTTPBasicAuth()
users = {
    "ydpl42": generate_password_hash("123456789"),
    "dmitry_kurch": generate_password_hash("123456789")
}
sessions = {}
storage = {}


def f(x):
    return '%.8f' % (math.exp(x) * math.cos(x))


def _is_expired(user):
    return user not in sessions or ('time' in sessions[user] and datetime.now().timestamp() - sessions[user]['time']  > INTERVAL)


def get_session_code(headers):
    return b64decode(headers.get('Session-Code')).decode('utf-8')


def get_x():
    return float('%.8f' % random.random())


def encode_x(x):
    return b64encode(str(x).encode('utf-8')).decode('utf-8')


def get_f(headers):
    return b64decode(headers.get('f-value')).decode('utf-8')


def is_expired(user):
    print(f'now: {datetime.now().timestamp()}')
    print(f'user: {user}: {sessions[user]}')
    t = _is_expired(user)
    print(f'Expired: {t}')
    return t


@auth.verify_password
def verify_password(username, password):
    print(username, password)
    if username in users:
        return check_password_hash(users.get(username), password)
    return False


@app.route("/")
def hello():
    return "Hello World!"


@app.route("/key", methods=['POST'])
@auth.login_required
def key():
    body = request.get_json()
    user = auth.username()
    session_code = get_session_code(request.headers)
    f_value = get_f(request.headers)
    if session_code != sessions[user]['code']:
        return json_message(None, 'Wrong session code. Please, relogin.'), 402
    elif sessions[user]['f'] != f_value:
        return json_message(None, 'Wrong value. Please, relogin.'), 402
    a = body['a']
    N = body['N']
    sessions[user]['crypto'] = AESCipher(generate_random_str())
    sessions[user]['time'] = datetime.now().timestamp()
    x = get_x()
    sessions[user]['f'] = f(x)
    response = app.response_class(
        response=key_message(GMS.encode(sessions[user]['crypto'].key_s, (a, N))),
        status=200,
        mimetype='application/json',
        headers={'x-value': encode_x(x)}
    )
    return response


@app.route("/store", methods=['POST'])
@auth.login_required
def store():
    user = auth.username()
    print(user)
    name = request.args.get(NAME)
    session_code = get_session_code(request.headers)
    f_value = get_f(request.headers)
    if is_expired(user):
        return json_message(None, 'Expired session code. Please, relogin.'), 401
    elif session_code != sessions[user]['code']:
        return json_message(None, 'Wrong session code. Please, relogin.'), 402
    elif sessions[user]['f'] != f_value:
        return json_message(None, 'Wrong value. Please, relogin.'), 402
    data = request.data
    crypto = sessions[user]['crypto']
    decrypted = crypto.decrypt(data)
    if DEBUG:
        print('Got data: ', data)
        print('Decrypted: ', decrypted)
        print('Saving data to file {}'.format(name))
    store_file(name, decrypted.decode('utf-8'))
    x = get_x()
    sessions[user]['f'] = f(x)
    response = app.response_class(
        response=normal_message('File {} is successfully saved.'.format(name)),
        status=200,
        mimetype='application/json',
        headers={'x-value': encode_x(x)}
    )
    return response


@app.route("/file", methods=['GET'])
@auth.login_required
def file():
    user = auth.username()
    name = request.args.get(NAME)
    session_code = get_session_code(request.headers)
    f_value = get_f(request.headers)
    if is_expired(user):
        return json_message(None, 'Expired session code. Please, relogin.'), 401
    elif session_code != sessions[user]['code']:
        return json_message(None, 'Wrong session code. Please, relogin.'), 402
    elif sessions[user]['f'] != f_value:
        return json_message(None, 'Wrong value. Please, relogin.'), 402
    crypto = sessions[user]['crypto']
    raw = get_file(name)
    data = crypto.encrypt(raw)
    if DEBUG:
        print('Raw data: ', raw)
        print('Encrypted: ', data)
    x = get_x()
    sessions[user]['f'] = f(x)
    response = app.response_class(
        response=io.BytesIO(data),
        status=200,
        mimetype='application/octet-stream',
        headers={'x-value': encode_x(x)}
    )
    return response


@app.route("/login")
@auth.login_required
def login():
    user = auth.username()
    code = generate_code()
    x = get_x()
    sessions[user] = {
        'code': code,
        'f': f(x)
    }
    bot.send_code(user, code)
    response = app.response_class(
        response=normal_message('We sent you code in telegram.'),
        status=200,
        mimetype='application/json',
        headers={'x-value': encode_x(x)}
    )
    return response


if __name__ == "__main__":
    bot_polling = threading.Thread(target=bot.get_bot().polling)
    bot_polling.start()
    app.run()
