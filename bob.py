###SAMPLE CODE FOR ONE PROCESS - "BOB" (INVERTING)##########################################

import socket   #for sockets
import sys  #for exit
 
# generate fresh random numbers for use in protocol:
from Crypto.Util import number
rB  = number.getRandomInteger(128)
rBp = number.getRandomInteger(128)
rBpp= number.getRandomInteger(128)

from Crypto.Hash import MD5
h = MD5.new()
secret = 12345678
h.update(str(secret))
Hs = h.digest()
print Hs

#PKAlice =
#SK =


try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
    print 'Failed to create socket'
    sys.exit()
print 'Socket Created'
host = '127.0.0.1'; #run everything on localhost
port = 4323;
 
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
message = "BOB" 
try :
    #Set the whole string
    s.sendall(message)
except socket.error:
    #Send failed
    print 'Send failed'
    sys.exit()
print 'Identification sent successfully'

urB  = u^rB%p
urBp = u^rBp%p
print "Generated ", urB, urBp

urA  = long(s.recv(128)) 	#receive message 1
urAp = long(s.recv(128))
s.sendall(str(urB))		#send message 2
s.sendall(str(urBp))	

print urA, urAp, urB, urBp
