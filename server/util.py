from flask import jsonify


def json_message(message, error=None):
    return jsonify(message=message, error=error)


def is_expired(user):
    return False


def get_file(name):
    with open('data/{}'.format(name), 'r') as fin:
        return ''.join(fin)


def store_file(name, data):
    with open('data/{}'.format(name), 'w') as fout:
        fout.write(data)


def generate_AES():
    pass


def encrypt(data, key):
    return data


def decrypt(data, key):
    return data