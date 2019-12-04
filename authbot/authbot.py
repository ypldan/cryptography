import telebot
import json

START_MESSAGE = "Hello! I'm the bot for authentication in Dima's and Danik's lab!\n" \
                "I'll send you codes when you try to log in encrypted notepad."
with open('users.json') as fin:
    USERS = json.load(fin)
print(USERS)

with open('token.txt', 'r') as fin:
    bot = telebot.TeleBot(''.join(fin))


def write_users():
    with open('users.json', 'w') as fout:
        json.dump(USERS, fout)


@bot.message_handler(commands=['start'])
def start_message(message):
    USERS[message.from_user.username] = message.chat.id
    write_users()
    bot.send_message(message.chat.id, START_MESSAGE)


def send_code(username, code):
    if username not in USERS:
        raise Exception(f'Cannot send to this user. {username} must start the bot firstly.')
    bot.send_message(USERS[username], code)


def get_bot():
    return bot


if __name__ == '__main__':
    send_code('ydpl42', 'Hej')