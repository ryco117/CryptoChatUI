CryptoChatUI
============

A secure, terminal based chat program that uses ECC Curve25519 or 4096 bit RSA keys to exchange a
256 bit AES key, which is used for the rest of the chat. The AES is done through the intel AES-NI instructions if they are available, else, my C++ wrapper (The AES-NI object is referenced but not included in this git project. It can be created using the code in my CryptoChat project). 
GMP is for large number arithmetic. 
The public and private keys generated can be stored to files to be reused. The private key may be encrypted
with 256 bit AES using a randomly generated IV and a key derived from a password using scrypt with
a random salt. Enjoy top-notch, uber-level secure chats (most often about security, you know it's
true :P ).