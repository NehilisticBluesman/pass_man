import argparse
import sys
import sqlite3
from sqlite3 import Error
import os
import time
from encrypt import *
from block_tracing import block_tracing


try:
    block_tracing()
except (NotImplementedError, OSError):
    print('block_tracing has fucked up')

def parser():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')

    a_parser = subparsers.add_parser('a')
    a_parser.add_argument('shortcut')
    a_parser.add_argument('login')
    a_parser.add_argument('password')

    cl_parser = subparsers.add_parser('cl')
    cl_parser.add_argument('login')

    cp_parser = subparsers.add_parser('cp')
    cp_parser.add_argument('password')

    first_parser = subparsers.add_parser('first')

    return parser

def first():
    check(['pmdb.db'])

    password = gen_pw()
    print('[*]Generating password...')
    print('[*]Savig creds...')
    hashed = derive_func(password)
    create_table('pmdb.db', 'topsecret', 'salt blob NOT NULL')
    make_entry('pmdb.db', (hashed[1],), 'topsecret', '(?)', chacha=False)

    create_table('pmdb.db', 'base', 'shortcut text NOT NULL, login text NOT NULL, password text NOT NULL, nonce blob NOT NULL')
    print('[+]Run "python pm.py a shortcut login password" to make first entry.')
    print('[Password]Keep it safely! ' + password)

def check(db):
    for i in db:
        try:
            f = open(i, 'x')
        except FileExistsError as e:
            print(e)
            print('[!]You already created database')
            exit()

def connect_db(db):
    con = None

    try:
        con = sqlite3.connect(db)
        return con
    except Error as e:
        print(e)

    return con

def make_entry(db,data,table,values,chacha=True):
    if chacha:
        key = auth()
        login, paswd, nonce = encrypt([data[1],data[2]], key)
        con = connect_db(db)
        cur = con.cursor()

        with con:
            cur.execute(f'INSERT INTO {table} VALUES {values}', (data[0], login, paswd, nonce))

            con.commit()
    else:
        con = connect_db(db)
        cur = con.cursor()

        with con:
            cur.execute(f'INSERT INTO {table} VALUES {values}', data)

            con.commit()

def create_table(db, table, fields):
    if not os.path.exists(db):
        with open(db, 'w+') as f:
            f.close()

    con = connect_db(db)
    cur = con.cursor()

    with con:
        cur.execute(f'CREATE TABLE IF NOT EXISTS {table}({fields})')
        con.commit()

def copy(field):
    con = connect_db('pmdb.db')
    cur = con.cursor()
    shortcut = sys.argv[2]

    with con:
        cur.execute(f'SELECT * FROM base {shortcut}')
        data = cur.fetchall()
    authentication = auth()
    to_copy = decrypt([data[0][1], data[0][2]], shortcut, authentication)
    os.system(f'wl-copy {to_copy[field]}')
    if field == 1:
        print('[I]Password copied to buffer')
    else:
        print('[I]Login copied to buffer')
    time.sleep(10)
    to_copy = 0
    os.system('wl-copy -c')
    print('[I]Buffer cleared')

create_parser = parser()
namespace = create_parser.parse_args(sys.argv[1:])

if namespace.command == 'first':
    first()
elif namespace.command == 'a':
    make_entry(db='pmdb.db',data=(sys.argv[2], sys.argv[3], sys.argv[4]),table='base',values='(?,?,?,?)')
elif namespace.command == 'cl':
    copy(0)
elif namespace.command == 'cp':
    copy(1)
