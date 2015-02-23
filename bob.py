###SAMPLE CODE FOR ONE PROCESS - "BOB" (INVERTING)##########################################

import socket   #for sockets
import sys  #for exit
 
from Crypto.Util import number      # generate fresh random numbers for 
rB  = number.getRandomInteger(128)  # use in protocol; 
rBp = number.getRandomInteger(128)
rBpp= number.getRandomInteger(128)

from Crypto.Hash import MD5
h = MD5.new()
secret = 12345678                   #manually define secret; same to be done for Bob
h.update(str(secret))               #then hash secret using MD5
Hs = h.digest()
print "Hash of secret: ", Hs

urB  = u^rB%p                       #exponentiate for Diffie-Hellman
urBp = u^rBp%p
print "Generated ", urB, urBp

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
    print 'Hostname could not be resolved. Exiting'
    sys.exit()
 
s.connect((remote_ip , port))				#Connect to remote server
print 'Socket Connected to ' + host + ' on ip ' + remote_ip
 
p = long(s.recv(512))	#receive Diffie-Hellman ingredients from server
u = long(s.recv(128))	#message 0 in protocol spec.
print("Received DH ingredients")

urA  = long(s.recv(128))    #receive message 1
urAp = long(s.recv(128))

urB  = u^rB%p
urBp = u^rBp%p
print "Generated ", urB, urBp

try :                       #send message 2
    s.sendall(str(urB))
except socket.error:
    print 'Send failed'
    sys.exit()
try :                       
    s.sendall(str(urBp))
except socket.error:
    print 'Send failed'
    sys.exit()

x     = (urA    ^ rB ) % p  # x=u^(r_ar_b) mod p
y     = (urAp   ^ rBp) % p  # y = u^(r'_ar'_b) mod p
xb    = (x^Hs)         % p  # x_b=H^H(s_b) known only by Bob
yrppb = (y^rBpp)       % p  # y^r''_b for fresh r''_b generated above

yrppa = long(s.recv(128))   # receive message 3
try :                       #send message 4
    s.sendall(str(yrppb))
except socket.error:
    print 'Send failed'
    sys.exit()

z = yrppa^rBpp      #known by both, to be used later in the check
bobCheck = xb ^ (u^(rBp))

aliceCheck = long(s.recv(128)) # message 5
try :                       #send message 6
    s.sendall(str(bobCheck))
except socket.error:
    print 'Send failed'
    sys.exit()

t = aliceCheck * bobCheck % p
try :                       #send message 7; disclose random
    s.sendall(str(rBp))
except socket.error:
    print 'Send failed'
    sys.exit()

rAp = long(s.recv(128))     #message 8

if (t^(rAp * rBp)) % p == z:
          print "The secrets match!"
    else: print "The secrets don't match."
s.close() #done
print urA, urAp, urB, urBp
