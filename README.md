# RSA Algorithm Using Hexidecimal Characters

A slightly modified demonstration of the traditional RSA algorithm. Generates an RSA public/private keypair based on random integers from 2-1000. Adding a slight modification on top of the existing algorithm, each character in an encrypted string generated from the base algorithm will be converted into a 5-digit hexidecimal number to add an extra layer of encryption.

To test the algorithm, the user inputs a message they would like encrypted. The program then encrypts the message and prints the result to the screen. The encrypted result is then decrypted and the result of this, being the original message, is printed to the screen.
