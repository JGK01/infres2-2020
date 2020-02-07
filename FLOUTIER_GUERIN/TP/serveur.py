# coding: utf-8
import socket
import msgpack
import sqlite3
import util
import random
import hashlib

from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

db = util.connectDB()
c = db.cursor()
util.checkDataBase(db)

sock = util.initSocket()

try:
    print("Waiting for connection...")
    sock.listen(1)
    client, address = sock.accept()
    print("{} connected\n".format(address))

    #DIFFIE HELLMAN
    hash_df_key = util.diffieHellman(client)
    cipherEncrypt = ChaCha20.new(key=hash_df_key)

    #AUTHENTIFICATION PAR CHALLENGE
    if util.challenge(client):
        print(f"\n{util.green}--------- CLIENT AUTHENTICATED ---------{util.white}\n")

        #RÉCUPÉRATION HISTORIQUE DANS DB
        util.readDataBase(db,address)
        #Réception du nonce client pour le décryptage
        nonce = msgpack.unpackb(client.recv(255))
        cipherDecrypt = ChaCha20.new(key=hash_df_key, nonce=nonce)

        client.send(msgpack.packb(cipherEncrypt.nonce))

        while True:
            msg_client = msgpack.unpackb(client.recv(255))
            if msg_client != "":
                    msg_client_decrypted = cipherDecrypt.decrypt(msg_client).decode("Utf8")
                    print (f"\nFrom {address[0]} : {msg_client_decrypted} ")
                    c.execute('INSERT INTO messages VALUES (?,?,?)', ("localhost", address[0], msg_client_decrypted))
                    db.commit()
                    msg_server = input("You : ")
                    if msg_server == "q":
                        client.close()
                    else:
                        c.execute('INSERT INTO messages VALUES (?,?,?)', (address[0], "localhost", msg_server))
                        db.commit()
                        msg_server_encrypted = cipherEncrypt.encrypt(msg_server.encode("Utf8"))
                        client.send(msgpack.packb(msg_server_encrypted))
    else:
        print("mauvais résultat")

except Exception as e:
    print(f"{util.red}")
    raise
finally:
    sock.close()
    db.close()
