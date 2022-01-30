from fastecdsa.curve import secp256k1
from fastecdsa.keys import export_key, gen_keypair

from fastecdsa import curve, ecdsa, keys, point
from hashlib import sha256

def sign(m):
	#generate public key
	#Your code here
	curve = secp256k1
	private_key, public_key = gen_keypair(curve)

	#generate signature
	#Your code here
	tup = ecdsa.sign(m,private_key)
	r = tup[0]
	s = tup[1]

	assert isinstance( public_key, point.Point )
	assert isinstance( r, int )
	assert isinstance( s, int )
	return( public_key, [r,s] )
