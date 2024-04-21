# COE817 - BANKING PROJECT 

## Protocol 
1. Server starts to run
2. Client connects to server
3. Client sends server a nonce encrypted with a previous a shared key
4. Use a key generating function to create a new key based on the nonce sent
** generates: encryption key, hmac key 
5.  Any message is now encrypted with the encrypytion key and a subsequent hmac is sent created with the hmac key
