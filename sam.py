###SAMPLE CODE FOR SERVER PROCESS - "SAM"#############################################################

import socket
import sys
from thread import *

#generate random large prime (p in specification)
from Crypto.Util import number
prime = number.getPrime(512)

#generate u coprime with p; Diffie-Hellman base
u = number.getRandomInteger(128)
import fractions
while fractions.gcd(u,prime)!=1:
	u = number.getRandomInteger(128)
print 'Crypto done.'

#from now on act as a socket server and just pass messages on
 
HOST = ''  			# listen on all connections
PORT = 4321
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print 'Socket created'

try:					#Bind socket to local host and port
    s.bind((HOST, PORT))
except socket.error , msg:
    print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
print 'Socket bind complete'

s.listen(10)				#Start listening on socket
print 'Socket now listening'

#Function for handling connections. This will be used to create threads
def clientthread(conn):
    while True:				#infinite loop so that function does 
        				#not terminate and thread does not end.
	conn.sendall(str(prime))	#start by passing Diffie-Hellman ingredients
	conn.sendall(str(u))		#as strings (message 0 in protocol spec)
        #Receiving from client
	name = conn.recv(128)		#client identification
	if name=="ALICE":
		urA = conn.recv(128)	#message 1
		urAp= conn.recv(128)
		conn.sendall(urB)
		conn.sendall(urBp)
				
	if name=="BOB":
		urB = conn.recv(128)	#message 2
		urBp= conn.recv(128)
		conn.sendall(urA)
		conn.sendall(urAp)
		
      #  reply = 'OK...' + data
      #  if not data:
      #      break    
      #  conn.sendall(reply)     
    conn.close()			#come out of loop
 
while 1:				#now keep talking to clients
    conn, addr = s.accept()		#wait to accept connection; blocking call
    print 'Connected with ' + addr[0] + ':' + str(addr[1])
    start_new_thread(clientthread ,(conn,))

s.close()
