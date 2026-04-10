# Secure-Messaging-Protocol

**Set-Up**
In order to use the server, you need to download *client.py* and the *server_pubkey.pem*. If you do not download the public key it will generate upon server start-up.

The server run command is the following:
- *python3 server.py --host HOST --port PORT*

The client run command is the following:
- *python3 client.py -u USERNAME --host HOST --port PORT*
*NOTE: if you wish to register a new user to the server, you can add -r to this in order to go through registration.*

Three test users are provided for testing purposes, the database that stores the password can be found in *users.json*. All of the architecture and protocols can be found in the PDF file provided.

**Test Users (Username, Password)**
- *User 1: alice, abc123*
- *User 2: bob, bcd234*
- *User 3: connor, cde345*