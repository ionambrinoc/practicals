###SAMPLE CODE FOR ONE PROCESS - "ALICE" (NON-INVERTING)##########################################

import socket   #for sockets
import sys  #for exit
 
# generate fresh random numbers for use in protocol:
from Crypto.Util import number
rA  = number.getRandomInteger(128)
rAp = number.getRandomInteger(128)
rApp= number.getRandomInteger(128)

from Crypto.Hash import MD5
h = MD5.new()
secret = 12345678		#manually define secret
h.update(str(secret))		#hash secret using MD5
Hs = h.digest()
print Hs

#PKBob = 
#SK    = 

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
    print 'Failed to create socket'
    sys.exit()
print 'Socket Created'
host = '127.0.0.1'; #run everything on localhost
port = 4322;
 
try:
    remote_ip = socket.gethostbyname( host ) 
except socket.gaierror:
    #could not resolve
    print 'Hostname could not be resolved. Exiting'
    sys.exit()
 
s.connect((remote_ip , port))				#Connect to remote server
print 'Socket Connected to ' + host + ' on ip ' + remote_ip
 
#Now receive data
p = long(s.recv(512))	#receive Diffie-Hellman ingredients from server
u = long(s.recv(128))	#message 0 in protocol spec.
print("Received DH ingredients")

#Send identification to server
message = "ALICE" 
try :
    #Set the whole string
    s.sendall(message)
except socket.error:
    #Send failed
    print 'Send failed'
    sys.exit()
print 'Identification sent successfully'

urA  = u^rA%p
urAp = u^rAp%p
print "Generated ", urA, urAp

s.sendall(str(urA))		#send message 1
s.sendall(str(urAp))	
urB  = long(s.recv(128)) 	#receive message 2
urBp = long(s.recv(128))

print urA, urAp, urB, urBp

