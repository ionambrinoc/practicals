###SAMPLE CODE FOR SERVER PROCESS - "ALICE"############################################################

import socket 				# note that Alice is one of the participants, the one who
import sys					# does not invert numbers modulo p; she acts as a server
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
secret = 12345678					#manually define secret; same to be done for Bob
h.update(str(secret))				#then hash secret using MD5
Hs = h.digest()
print "Hash of secret: ", Hs

urA  = u^rA %p             			#exponentiate for Diffie-Hellman
urAp = u^rAp%p
print "Generated ", urA, urAp

print len(str(urA))
print len(str(u))
print len(str(urAp))

#cryptographic component generation now done.
#from now on act as a socket server and just pass messages on

HOST = 'localhost'  			# listen on all connections
PORT = 4326
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
	print 'sent ' + str(p) + ' and '+str(u)+' as message 0'
        

	conn.sendall(str(urA))		# message 1: two Diffie-Hellman messages.
	conn.sendall(str(urAp))
	print 'sent '+str(urA)+' and '+str(urAp)+' as message 1'

	urB = long(conn.recv(129))	# message 2: Bob's corresponding D-H messages.
	urBp= long(conn.recv(129))  # reconverted into (useful) longs.
	print 'got '+str(urB)+' and '+str(urBp)+' as message 2'

	x     = (urB    ^ rA ) % p 	# x=u^(r_ar_b) mod p
	y     = (urBp   ^ rAp) % p 	# y = u^(r'_ar'_b) mod p
	xa 	  = (x^Hs)         % p	# x_a=x^H(s_a), known by Alice only
	yrppa = (y^rApp)	   % p  # y^r''_a for fresh r''_a generated above 
	print 'computed' + str(x) +' and '+str(y)+' and '+str(xa)+' and '+str(yrppa)   

	conn.sendall(str(yrppa))    # message 3
	print 'sent '+str(yrppa)+' as message 3'
	yrppb = long(conn.recv(129))# message 4, from Bob: y^(-r''_b)
	print 'got '+str(yrppb)+' as message 4'

	z = yrppb^rApp			  % p   # known by both, to be used later in the check.
	aliceCheck = xa*(u^(rAp)) % p
	print 'computed' + str(z) +' and '+str(aliceCheck)

	conn.sendall(str(aliceCheck))   # message 5, relying  on hash and discrete 
									# to ensure secret is not leaked; this is the
									# only place where a function of the secret is
									# actually transferred between Alice and Bob.
	print 'sent '+str(aliceCheck)+' as message 5'
	bobCheck = long(conn.recv(129)) # message 6, Bob's analogous to 5.
	print 'got '+str(bobCheck)+' as message 6'

	t = aliceCheck * bobCheck % p

	rBp = long(conn.recv(129))		# reverse message order; Bob discloses one of the 
	if (u^rBp) % p != urBp:
		print "BOB IS LYING, DROPPING CONNECTION"
		s.close()					#and drop connection; otherwise...
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
