from flask import Flask, request, jsonify
import rsa
from util import *

USER = 'user'
NAME = 'name'
app = Flask(__name__)
users = {'Daniil', 'Dmitry', 'test'}
sessions = {}
storage = {}


@app.route("/")
def hello():
    return "Hello World!"


@app.route("/store", methods=['POST'])
def store():
    user = request.args.get(USER)
    name = request.args.get(NAME)
    if user not in users or is_expired(user):
        return json_message(None, 'No such user.'), 400
    elif is_expired(user):
        return json_message(None, 'Session is expired.'), 401
    data = request.get_json()['data']
    return json_message('File {} is successfully saved.'.format(name)), 200


@app.route("/key", methods=['POST'])
def key():
    body = request.get_json()
    user = request.args.get(USER)
    if user not in users:
        return json_message(None, "No such user."), 400
    pub = body['public_key']
    sessions[user] = rsa.encrypt(generate_AES(), pub)
    return json_message(sessions[user]['key'])


@app.route("/file", methods=['GET'])
def file():
    user = request.args.get(USER)
    name = request.args.get(NAME)
    if user not in users or is_expired(user):
        return json_message(None, 'No such user.'), 400
    elif is_expired(user):
        return json_message(None, 'Session is expired.'), 401
    key = sessions[user]['key']
    data = encrypt(get_file(name), key)
    return json_message(data), 200


if __name__ == "__main__":
    app.run()
