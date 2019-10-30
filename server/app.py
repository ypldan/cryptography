from flask import Flask, request, send_file
import io
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from util import *
import time


USER = 'user'
NAME = 'name'
DEBUG = True
app = Flask(__name__)
users = {'Daniil', 'Dmitry', 'test'}
sessions = {}
storage = {}


def is_expired(user):
    return user not in sessions


@app.route("/")
def hello():
    return "Hello World!"


@app.route("/key", methods=['POST'])
def key():
    body = request.get_json()
    user = request.args.get(USER)
    if user not in users:
        return json_message(None, "No such user."), 400
    pub = RSA.import_key(body['pub'])
    sessions[user] = {
        'crypto': AESCipher(),
        'time': time.time()
    }
    encoder = PKCS1_OAEP.new(pub)
    return send_file(io.BytesIO(encoder.encrypt(sessions[user]['crypto'].key_s.encode('utf-8'))),
                                mimetype='application/octet-stream')


@app.route("/store", methods=['POST'])
def store():
    user = request.args.get(USER)
    name = request.args.get(NAME)
    if user not in users:
        return json_message(None, 'No such user.'), 400
    elif is_expired(user):
        return json_message(None, 'Session is expired.'), 401
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
def file():
    user = request.args.get(USER)
    name = request.args.get(NAME)
    if user not in users:
        return json_message(None, 'No such user.'), 400
    elif is_expired(user):
        return json_message(None, 'Session is expired.'), 401
    crypto = sessions[user]['crypto']
    raw = get_file(name)
    data = crypto.encrypt(raw)
    if DEBUG:
        print('Raw data: ', raw)
        print('Encrypted: ', data)
    return send_file(io.BytesIO(data),
                     mimetype='application/octet-stream')


if __name__ == "__main__":
    app.run()
