# COE817 - BANKING PROJECT 

## Protocol 
1. Server starts to run
2. Client connects to server
3. Client sends server a nonce encrypted with a previous shared key
4. Use a key generating function to create a new key based on the nonce sent
    - generates: encryption key, HMAC key 
5. Any message is now encrypted with the encryption key and a subsequent HMAC is created with the HMAC key

![image](https://github.com/saikot-paul/COE817-PROJECT/assets/79386282/0bf7d45c-698a-40d3-8d51-6ab9e13e31b9)

