##############################ADVANCED SECURITY PRACTICAL ASSIGNMENT 1###############################
###########################CRYPTOGRAPHY FOR PRIVACY####HILARY TERM 2015##############################

"""PROTOCOL IDEA AND SPECIFICATION-------------------------------------------------------------------
0. Sam   -> Alice, Bob:  prime p, u coprime with p		       --server prepares (double) D-H
1. Alice -> Bob       :  u^r_a, u^r'_a				       --fresh random numbers r_a,r'_a
2. Bob   -> Alice     :  u^r_b, u^r'_b                                 --fresh random numbers r_b,r'_b

   [both now know x=u^(r_ar_b), y=u^(r'_ar'_b); Alice knows x_a = x^H(s_a), Bob knows x_b = x^H(s_b)]
   [H is a hash function; communication is done through HTTP server Sam; we abstract away from this ]
3. Alice -> Bob       : y^r''_a					       --fresh random number r''_a
4. Bob   -> Alice     : y^(-r''_b)				       --fresh random number r''_b

   [both now know z=y^(r''_a-r''_b) which will later be used in the check]

5. Alice -> Bob       : x_a 	* u^(r'_a)			       --relying on DiscreteLog Problem
6. Bob   -> Alice     : x_b^(-1)* u^(-r'_b)			       --for nondisclosure
7. Bob   -> Alice     : r'_b
8. Alice -> Bob	      : r'_a					       --cross-disclose it

   [both form t=x_a* u^(r'_a)*x_b^(-1)* u^(-r'_b); then they check if t^(r'_ar'_b)==z <==>s_a==s_b  ]
   [Alice additionally checks if Bob is lying: if u^(r'_b(10)) != u^(r'_b)(2), then he is!          ]

Protocol strengths: Alice can detect whether Bob has been dishonest; Bob commits to x_b at message 6,
		    so he cannot lie when he sends it there and keep another true x_b for which he
		    finds out the answer; what he can do is send Alice a fake random number at step 7;
		    at which point Alice does the above check and finds out if he is being dishonest.

		    Further, the information leaked is minimal: the only time the secret is sent over
		    the network is at messages 5 and 6, at which point it is heavily hashed, so very
		    little (if any) information about it is leaked.

		    We can also implement this on top of SSL/TLS to ensure privacy and confidentiality
		    of the messages, to provide security against a Dolev-Yao attacker. Note also the
		    forward secrecy: due to hashing and the Discrete Log problem, an attacker can find
		    out, at most, if the two values were equal, and not the values themselves.

		    Finally, note that there are only 8 messages exchanged, an arguably small number.

Proof of work: t^(r'_ar'_b)=(x_ax_b^(-1))u^(r'_ar'_b(r''_ar''_b)) = 1 * z since s_a=s_b => x_a=x_b"""

# I have run into implementation problems in the Python code, specifically in the transmission
# of messages over TCP/IP, with failures occurring nondeterministically throughout the code.

# Extra assumption: we assume that we are working over authenticated secure channels (eg TLS), 
# in order to simplify implementation (this is why we are not sending encrypted information).

###SAMPLE CODE FOR SERVER PROCESS - "ALICE"#####(as server to simplify implementation)###############

import socket 				# note that Alice is one of the participants, the one who
import sys				# does not invert numbers modulo p; she acts as a server
from thread import *		# for simplicity of implementation only, and this is not
				# necessary for the purposes of the (abstract) protocol.

from Crypto.Util import number   # generate random large prime (p in specification)
prime = number.getPrime(512)	 # (first ingredient for Diffie-Hellman); all
p = prime
u = number.getRandomInteger(128) # generate u coprime with p; Diffie-Hellman base
import fractions				 # (second ingredient for Diffie-Hellman)
while fractions.gcd(u,prime)!=1:
	u = number.getRandomInteger(128)

from Crypto.Util import number 		# generate fresh random numbers for 
rA  = number.getRandomInteger(128)	# use in protocol; Bob also does this step
rAp = number.getRandomInteger(128)
rApp= number.getRandomInteger(128)
from Crypto.Hash import MD5
h = MD5.new()
secret = 12345678				#manually define secret; same to be done for Bob
h.update(str(secret))				#then hash secret using MD5
Hs = h.digest()
print "Hash of secret: ", h.hexdigest()
urA  = (u^rA) %p             			#exponentiate for Diffie-Hellman
urAp = (u^rAp)%p
print "Generated ", hex(urA), hex(urAp)
#cryptographic component generation now done.
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

#Function for handling connections, to be used to create thread for Bob;
#very simplified to make not a general socket server, but one that strictly
#carries out required protocol with Bob.
def clientthread(conn):
	conn.sendall(str(prime))	# message 0: pass Bob ingredients for Diffie-Hellman
	conn.sendall(str(u))		# as strings (sendall does not take longs)
	print 'sent ' + hex(p) + ' and '+ hex(u) +' as message 0'
        

	conn.sendall(str(urA))		# message 1: two Diffie-Hellman messages.
	conn.sendall(str(urAp))
	print 'sent '+ hex(urA) + ' and ' + hex(urAp) + ' as message 1'

	urB = long(conn.recv(4096))	# message 2: Bob's corresponding D-H messages.
	urBp= long(conn.recv(4096))  # reconverted into (useful) longs.
	print 'got '+ hex(urB) + ' and ' + hex(urBp) + ' as message 2'

	x     = (urB    ^ rA ) % p 	# x=u^(r_ar_b) mod p
	y     = (urBp   ^ rAp) % p 	# y = u^(r'_ar'_b) mod p
	xa 	  = (x^Hs)         % p	# x_a=x^H(s_a), known by Alice only
	yrppa = (y^rApp)	   % p  # y^r''_a for fresh r''_a generated above 
	print 'computed' + str(x) +' and '+str(y)+' and '+str(xa)+' and '+str(yrppa)   
	conn.sendall(str(yrppa))    # message 3
	print 'sent '+str(yrppa)+' as message 3'
	yrppb = long(conn.recv(4096))# message 4, from Bob: y^(-r''_b)
	print 'got '+str(yrppb)+' as message 4'

	z = yrppb^rApp			  % p   # known by both, to be used later in the check.
	aliceCheck = xa*(u^(rAp)) % p
	print 'computed' + str(z) +' and '+str(aliceCheck)

	conn.sendall(str(aliceCheck))   # message 5, relying  on hash and discrete 
					# to ensure secret is not leaked; this is the
					# only place where a function of the secret is
					# actually transferred between Alice and Bob.
	print 'sent '+str(aliceCheck)+' as message 5'
	bobCheck = long(conn.recv(4096)) # message 6, Bob's analogous to 5.
	print 'got '+str(bobCheck)+' as message 6'

	t = aliceCheck * bobCheck % p
	rBp = long(conn.recv(4096))		# reverse message order; Bob discloses one of the 
	if (u^rBp) % p != urBp:
		print "BOB IS LYING, DROPPING CONNECTION"
		s.close()				#and drop connection; otherwise...
	conn.sendall(str(rAp))			# message 8; do the same as Bob

	if (t^(rAp * rBp)) % p == z:
		print "The secrets match!"
	else: print "The secrets don't match."

  	conn.close()				#come out of loop
while 1:						#now talk to Bob
    conn, addr = s.accept()		#wait to accept connection; blocking call
    print 'Connection accepted'
    print 'Connected with ' + addr[0] + ':' + str(addr[1]) + 'as Bob'
    start_new_thread(clientthread ,(conn,))
s.close()

###SAMPLE CODE FOR ONE PROCESS - "BOB" (INVERTING)###(as client to simplify implementation)##########

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
print "Hash of secret: ", h.hexdigest()

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
    print 'Failed to create socket'
    sys.exit()
print 'Socket Created'
host = ''; #run everything on localhost
port = 4321;
 
try:
    remote_ip = socket.gethostbyname( host ) 
except socket.gaierror:
    print 'Hostname could not be resolved. Exiting'
    sys.exit()
 
s.connect((remote_ip , port))				#Connect to remote server
print 'Socket Connected to ' + host + ' on ip ' + remote_ip
 
p = long(s.recv(4096))	#receive Diffie-Hellman ingredients from server
u = long(s.recv(4096))	#message 0 in protocol spec.
print "Received DH ingredients " + hex(p) + ' and ' + hex(u)

urB  = u^rB%p                       #exponentiate for Diffie-Hellman
urBp = u^rBp%p
print "Generated ", hex(urB), hex(urBp)

urA  = long(s.recv(4096))   #receive message 1
print "Received "+hex(urA)
urAp = long(s.recv(4096))
print "Received " + hex(urA) + " and " + urAp + " as message 1"

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

yrppa = long(s.recv(4096))   # receive message 3
try :                       #send message 4
    s.sendall(str(yrppb))
except socket.error:
    print 'Send failed'
    sys.exit()

z = yrppa^rBpp      #known by both, to be used later in the check
bobCheck = xb ^ (u^(rBp))

aliceCheck = long(s.recv(4096)) # message 5
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

rAp = long(s.recv(4096))     #message 8

if (t^(rAp * rBp)) % p == z:
          print "The secrets match!"
else: print "The secrets don't match."
s.close() #done
print urA, urAp, urB, urBp
