import socket
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import msgpack
import random
import sqlite3
import hashlib

sel = b"9\x80\x9bz\xde\xd04JH-1G\xc34\x06B'}f\x0e\x8apr\xe92\x8d$-I\xd7\x96_"

#Diffie Hellman params
g=9
p=1001
my_random= random.randint(5, 10)
A=(g**my_random)%p


#socker params
hote = "159.31.59.130"
port = 15558

#COnfiguration & Save to base
conn = sqlite3.connect('database2.db')
c = conn.cursor()
c.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='messages' ''')

if c.fetchone()[0]==1 :
	print('Database exists')
else:
    c.execute('''CREATE TABLE messages(sender text, receiver text, message text)''')
    conn.commit()

#Socker connection
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((hote, port))
print ("Connection on {}".format(port))

#Diffie Hellman send params
params = [g, p, A]
socket.send(msgpack.packb(params))

#Diffie Hellman receive params
B=msgpack.unpackb(socket.recv(255))
our_key=(B**my_random)%p
hash_our_key = hashlib.sha256(str(our_key).encode()).digest()
print("the secret key : {}".format(our_key))

#Authentification Challenge
challenge=msgpack.unpackb(socket.recv(255))
mot_de_passe = input("Mot de passe : ")
hash = hashlib.sha256(b"9\x80\x9bz\xde\xd04JH-1G\xc34\x06B'}f\x0e\x8apr\xe92\x8d$-I\xd7\x96_" +  mot_de_passe.encode()).hexdigest()
challenge_response = msgpack.packb(hashlib.sha256(hash.encode() + challenge).hexdigest())
socket.send(challenge_response)

#Print previous conversation stocked in base
query = f"SELECT * FROM messages"
c.execute(query)
rows = c.fetchall()
for row in rows:
    if row[0] == 'localhost':
        print("\nlocalhost : {}".format(row[2]))
    else:
        print(f"{row[0]} : {row[2]}")


#Encrypt message
cipher = ChaCha20.new(key=hash_our_key)
socket.send(msgpack.packb(cipher.nonce))

nonce = msgpack.unpackb(socket.recv(255))
cipher2 = ChaCha20.new(key=hash_our_key, nonce=nonce)

while True :
    my_msg = input("Message : ").encode("Utf8")
    my_msg_encrypted = cipher.encrypt(my_msg)
    my_msg_serial=msgpack.packb(my_msg_encrypted)

    socket.send(my_msg_serial)
    c.execute('INSERT INTO messages VALUES (?,?,?)', ("localhost", "server", my_msg.decode("Utf8")))
    conn.commit()

    response = msgpack.unpackb(socket.recv(255))
    final_msg = cipher2.decrypt(response).decode("Utf8")
    print("server : {}".format(final_msg))
    c.execute('INSERT INTO messages VALUES (?,?,?)', ("server", "localhost", final_msg))
    conn.commit()

print ("Close")
socket.close()
