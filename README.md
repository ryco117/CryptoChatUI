CryptoChatUI
============

A secure, chat program that uses ECC Curve25519 or 4096 bit RSA keys to exchange a
256 bit AES key, which is used for the rest of the chat. It uses GMP for it's large number arithmetic. 
The public and private keys generated can be stored to files to be reused. The private key may be encrypted
with 256 bit AES using a randomly generated IV and a key derived from a password using scrypt with
a random salt. It is the successor to the original CryptoChat and maintains complete compatibility with it,
but with a nice Qt based graphical interface. Enjoy top-notch, uber-level secure chats (most often about security, you know it's
true :P ).
