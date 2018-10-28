"""
Tim Lanzi
COSC 370

RSA Encryption algorithm using 5 digit hexidecimal numbers for each character

References:
RSA (cryptosystem) - Wikipedia
	https://en.wikipedia.org/wiki/RSA_(cryptosystem)
	(used for the general algorithm)
	
Extended Euclidean algorithm - Wikipedia
	https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
	(used for the multiplicativeInverse() function to generate the private key)
	
Euclidean algorithm - Wikipedia
	https://en.wikipedia.org/wiki/Euclidean_algorithm
	(used for the gcd() function for determining whether two numbers are coprime)
"""

# used for randomizing the prime numbers used to create the keys
import random

# function determines whether a number is a prime number
def isPrime(num):
	if num == 2:
		return True
	elif num < 2 or num % 2 == 0:
		return False
	else:
		for n in range(3, int((num**0.5) + 2), 2):
			if num % n == 0:
				return False
		return True
		
# greatest common divisor function
# used to determine whether to numbers are coprime
def gcd(one, two):
	while two != 0:
		one, two = two, one % two
	return one

# multiplicative inverse function
# generates the private key
# reference for this algorithm was the "Extended Euclidean algorithm" page
# from Wikipedia	
def multiplicativeInverse(e, phi):
	t = 0
	newt = 1
	r = phi
	newr = e
	
	while newr > 0:
		quotient = int(r / newr)
		t, newt = newt, (t - quotient*newt)
		r, newr = newr, (r - quotient*newr)
	
	if r > 1:
		print("Cannot be inversed") 
	if t < 0:
		t = t + phi
	return t

# this function generates the public and private keypairs
def genKeypair():
	# generate a random number and make sure it is a prime number
	p = random.randint(2, 1000)
	while (not isPrime(p)):
		p = random.randint(2, 1000)
	
	# generate a second random number, make sure it is prime, a make 
	# sure it isn't the same number as p
	q = random.randint(2, 1000)
	while (not (isPrime(q) and p != q)):
		q = random.randint(2, 1000)
	
	# modulus for the public and private keys
	n = p * q

	# calculate the totient of p and q
	phi = (p - 1) * (q - 1)
	
	# Pick a random integer e, s.t. 1 < e < phi, and e is coprime to phi.
	# Once this number is found, e will be our public key exponent
	e = random.randint(1, phi)
	g = gcd(phi, e)		# check the greatest common divisor of e and phi
	
	# continue searching for a number e until the gcd of e and phi is 1
	# (meaning e and phi are coprime)
	while (g != 1):
		e = random.randint(1, phi)
		g = gcd(phi, e)
	
	# d is the multiplicative inverse of e and phi.
	# Once d is found, d will be our private key exponent
	d = multiplicativeInverse(e, phi)
	
	# return the public and private keypairs
	return ((e, n), (int(d), n))
	
# Encrypts a given message using the public keypair.
# An extra step I added is convering each character in encMsg into a 
# 5 digit hexidecimal number before returning the message.
def encrypt(keypair, msg):
	key, n = keypair
	
	# Each character c is converted into its decimal value via the ord() function.
	# This value is then used in the formula: encChar = c^n mod key
	# where n is the modulus of the public and private keys (e) and key 
	# is the public key
	encMsg = [pow(ord(c), key, n) for c in msg]
	
	# convert each character from encMsg into a 5 digit hex number
	hexStr = ''
	for letter in encMsg:
		hexChar = '{:05x}'.format(letter)
		hexStr = hexStr + hexChar
	
	# return the hex string
	return hexStr
	
# Decrypts the message that was encrypted by the public keypair by using 
# the private keypair
def decrypt(keypair, msg):
	key, n = keypair
	
	# convert the hex string back into regular characters
	encMsg = []
	for i in range(0,len(msg), 5):
		hexStr = msg[i:i+5]
		encMsg.append(int(hexStr,16))
	
	# Each character c is put through the following formula:
	# c^key mod n
	# where key is the private key and n is the modulus of the public and
	# private keys (e). This character is then converted back into its 
	# ascii value via the chr() function
	decMsg = [chr(pow(c, key, n)) for c in encMsg]
	
	# return the decrypted message
	return ''.join(decMsg)
	
# Main function to demo the algorithm
if __name__ == '__main__':
	# seed used in testing
	#random.seed(123)
	
	# generate the public and private keypairs
	print("Generating RSA keypair...")
	public, private = genKeypair()
	print("Done!")
	
	# display the public and private keypairs
	print("Public Key: ", public)
	print("Private Key: ", private)
	
	# input a message to encrypt which will be printed
	message = input("\nEnter a message:  ")
	encMessage = encrypt(public, message)
	print("\nEncrypted message: ", encMessage, "\n")
	
	# decrypt the message and print it
	decMessage = decrypt(private, encMessage)
	print("Decrypted message: ", decMessage, "\n")
	
