##############################ADVANCED SECURITY PRACTICAL ASSIGNMENT 1#################################
###########################CRYPTOGRAPHY FOR PRIVACY####HILARY TERM 2015################################

"""PROTOCOL IDEA AND SPECIFICATION---------------------------------------------------------------------

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
###SAMPLE CODE FOR SERVER PROCESS - "SAM"#############################################################
import socket   #using example provided in practical manual
import sys

HOST = ''	# Symbolic name, meaning all available interfaces
PORT = 4321
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:					#Bind socket to local host and port
	s.bind((HOST, PORT))
except socket.error as msg:
	print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	sys.exit()	
print 'Socket bind complete'
s.listen(10) #Start listening on socket

#Function for handling connections. This will be used to create threads
def clientthread(conn):	
	while True: #infinite loop so that function do not terminate and thread do not end.		
		data = conn.recv(1024) #Receiving from client
		reply = 'OK...' + data
		if not data: break	
		conn.sendall(reply)	
	conn.close() #come out of loop

while 1:				        #now keep talking with the client
	conn, addr = s.accept()	     #wait to accept a connection - blocking call
	print 'Connected with ' + addr[0] + ':' + str(addr[1])	#start new thread
	#taking 1st argument as a function name to be run, second is the tuple of 
	start_new_thread(clientthread ,(conn,)) #arguments to the function.
s.close()
   
