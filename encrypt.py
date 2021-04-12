import base64
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import openssl
from cryptography.exceptions import InvalidKey, InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import secrets
import string
import sqlite3
from sqlite3 import Error
from getpass import getpass


def gen_pw():
    checker = 0
    while checker == 0:
        try:
            length = int(input('[+]Lenght of password: '))
        except ValueError:
            print('[!]Input must be integer')
            exit()
        if length < 12:
            print('[!]Atleast 12 characters required')
            exit()
        elif length >= 12 and isinstance(length, int):
            checker = 1

    return ''.join((secrets.choice(string.ascii_letters + string.digits) for i in range(length)))

def derive_func(password, salt=os.urandom(16)):
    kdf = Scrypt(
        salt = salt,
        length = 32,
        n = 2**14,
        r = 8,
        p = 1,
        backend = openssl.backend
    )

    return [kdf.derive(password.encode()), salt]

def auth():
    password = getpass()

    con = None
    try:
        con = sqlite3.connect('pmdb.db')
    except Error as e:
        print(e)
    cur = con.cursor()
    with con:
        cur.execute('SELECT * FROM topsecret')
        salt = cur.fetchone()
    der_pw = derive_func(password, salt[0])

    return der_pw[0]

def encrypt(data, key):
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)

    final = []
    for i in [x.encode() for x in data]:
        ed = chacha.encrypt(nonce, i, None)
        final.append(ed)

    return final[0], final[1], nonce


def decrypt(data, shortcut, key): #Catch exception InvalidTag
    con = None
    try:
        con = sqlite3.connect('pmdb.db')
    except Error as e:
        print(e)
    cur = con.cursor()
    with con:
        cur.execute(f'SELECT nonce FROM base {shortcut}')
        nonce = cur.fetchall()
    chacha = ChaCha20Poly1305(key)
    final = []
    for i in data:
        try:
            ed = chacha.decrypt(nonce[0][0], i, None)
            final.append(ed.decode('utf-8'))
        except InvalidTag:
            print('[!]Incorrect password: permission denied')
            exit()

    return final

