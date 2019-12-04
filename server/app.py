from flask import Flask, request, send_file
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import io
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from util import *
import time
import authbot as bot
import threading


NAME = 'name'
DEBUG = True
app = Flask(__name__)
auth = HTTPBasicAuth()
users = {
    "ydpl42": generate_password_hash("123456789"),
    "dmitry_kurch": generate_password_hash("123456789")
}
sessions = {}
storage = {}


def is_expired(user):
    return user not in sessions


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
    print(user)
    session_code = request.headers.get('Session-Code')
    if is_expired(user):
        return json_message(None, 'Expired session code. Please, relogin.'), 401
    elif session_code != sessions[user]['code']:
        print(sessions[user])
        print(session_code)
        return json_message(None, 'Wrong session code. Please, relogin.'), 402
    pub = RSA.import_key(body['pub'])
    sessions[user]['crypto'] = AESCipher(generate_random_str())
    sessions[user]['time'] = time.time()
    print(sessions[user])
    encoder = PKCS1_OAEP.new(pub)
    return send_file(io.BytesIO(encoder.encrypt(sessions[user]['crypto'].key_s.encode('utf-8'))),
                                mimetype='application/octet-stream')


@app.route("/store", methods=['POST'])
@auth.login_required
def store():
    user = auth.username()
    print(user)
    name = request.args.get(NAME)
    session_code = request.headers.get('Session-Code')
    if is_expired(user):
        return json_message(None, 'Expired session code. Please, relogin.'), 401
    elif session_code != sessions[user]['code']:
        print(sessions[user])
        print(session_code)
        return json_message(None, 'Wrong session code. Please, relogin.'), 402
    data = request.data
    crypto = sessions[user]['crypto']
    decrypted = crypto.decrypt(data)
    if DEBUG:
        print('Got data: ', data)
        print('Decrypted: ', decrypted)
        print('Saving data to file {}'.format(name))
    store_file(name, decrypted.decode('utf-8'))
    return json_message('File {} is successfully saved.'.format(name)), 200


@app.route("/file", methods=['GET'])
@auth.login_required
def file():
    user = auth.username()
    print(user)
    name = request.args.get(NAME)
    session_code = request.headers.get('Session-Code')
    if is_expired(user):
        return json_message(None, 'Expired session code. Please, relogin.'), 401
    elif session_code != sessions[user]['code']:
        return json_message(None, 'Wrong session code. Please, relogin.'), 402
    crypto = sessions[user]['crypto']
    raw = get_file(name)
    data = crypto.encrypt(raw)
    if DEBUG:
        print('Raw data: ', raw)
        print('Encrypted: ', data)
    return send_file(io.BytesIO(data),
                     mimetype='application/octet-stream')


@app.route("/login")
@auth.login_required
def login():
    user = auth.username()
    code = generate_code()
    sessions[user] = {
        'code': code
    }
    bot.send_code(user, code)
    return json_message('We send you code in telegram.')


if __name__ == "__main__":
    bot_polling = threading.Thread(target=bot.get_bot().polling)
    bot_polling.start()
    app.run()
