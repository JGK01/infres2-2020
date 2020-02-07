import sqlite3
import socket
import hashlib
import msgpack
import string, random
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

white = '\033[0m'
green = '\033[92m'
red = '\033[91m'

#-------------------------------------DATABASE-------------------------------------------#
def connectDB():
    return sqlite3.connect('database.db')

def checkDataBase(db):

    print("--------- CHECKING DATABASE ---------")
    c = db.cursor()

    c.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='messages' ''')
    if c.fetchone()[0]==1 :
    	print('Table messages already exists')
    else:
        print('Creating messages table')
        c.execute('''CREATE TABLE messages(sender text, receiver text, message text)''')
        db.commit()

    print(f"{green}--------- DATABASE OK ---------\n{white}")

def readDataBase(db, address):

    print("--------- READING DATABASE ---------")
    query = f"SELECT * FROM messages WHERE sender='{address[0]}' OR receiver='{address[0]}'"
    c = db.cursor()
    c.execute(query)
    rows = c.fetchall()
    for row in rows:
        if row[0] == 'localhost':
            print("\nlocalhost : {}".format(row[2]))
        else:
            print(f"{row[0]} : {row[2]}")

    print(f"{green}--------- READING DATABASE OK ---------\n{white}")

#-------------------------------------CHALLENGE-------------------------------------------#
def getChallenge():
    return ''.join([random.choice(string.ascii_letters + string.digits) for n in range(32)])

def getResponse(challenge):
    # Hash client : 5748aa62ef5ccd576ead18b137cbba517677b82573aa9c16db14ca43f8430ed3
    m = hashlib.sha256("5748aa62ef5ccd576ead18b137cbba517677b82573aa9c16db14ca43f8430ed3".encode() +  challenge.encode())
    return m.hexdigest()

def challenge(client):
    print("--------- CHALLENGE AUTHENTICATION ---------")
    challenge = getChallenge()
    client.send(msgpack.packb(challenge))
    response = msgpack.unpackb(client.recv(255))
    return response.decode() == getResponse(challenge)


#-------------------------------------SOCKET-------------------------------------------#
def initSocket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 15558))
    return sock

#-------------------------------------DIFFIE HELLMAN-------------------------------------------#

def diffieHellman(client):
    print("--------- DIFFIE HELMANN ---------")
    print("Waiting for parameters.. ")
    my_secret_random = random.randint(5, 10)
    parameters = msgpack.unpackb(client.recv(255))
    generator = parameters[0]
    prime = parameters[1]
    a = parameters[2]
    b = (generator ** my_secret_random) % prime
    client.send(msgpack.packb(b))

    print("Calculating key.. ")
    df_key = (a ** my_secret_random) % prime

    print("Diffie-Hellman key :{}".format(df_key))
    print(f"{green}--------- DIFFIE HELMANN OK ---------\n{white}")

    return hashlib.sha256(str(df_key).encode()).digest()
