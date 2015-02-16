##############################ADVANCED SECURITY PRACTICAL ASSIGNMENT 1#################################
###########################CRYPTOGRAPHY FOR PRIVACY####HILARY TERM 2015################################

#######################################################################################################
""" PROTOCOL SPECIFICATION. 

[A knows a not b; B knows b not a; each has a random number r_a, r_b]

1. A -> B : {m, m_a=m^a, n_a=m^a'}_B		
2. B -> A : {m_b=m^b, n_b =m^b'}_A
[at this point, they both have M=m^(ab), N=m^(a'b') - 2xDiffie-Hellman up to here]
3. A -> B: {N^r_a, M^r_a * N^s_a}_B
4. B -> A: {N^r_b, M^r_b * N^s_b}_A
[each checks that N^r_a * (M^r_a * N^s_a)^(-1) = N


Protocol advantages: 2 parties only, minimal number of messages, minimal information leakage
Forward secrecy: if the encryption is broken, the only thing that can leak is the hash in (3).



				   								"""

from Crypto import Random
print("boss")
