## Generating certificates

The server needs a certificate before it can run. Make sure you have `libssl-dev` installed. Generate the CA and the server certificate with:

```
make certs
```

This creates everything under the `certs/` folder (the CA, the server key, and
the server certificate signed by that CA).

## Running Code

just run the make, `Makefile` already included in folder, so it'll create two binaries `client` and `server`. Then execute them directly, either in docker (docker compose included)

To run make:

```
make && ./server && ./client
```

> change server IP in constants.h according to your machine.

Then for running MITM `mallory`, you also need to do arp spoofing. 

for arp spoofing, make sure you have `libssl-dev`  and `iptables` packages installed.


First run the following for updating IP tables

```
iptables -t nat -A PREROUTING -p tcp --dport 8000 -j REDIRECT --to-ports 8000
```

> Make sure to update IP and Mac addresses for server and client in arp_spoof.cpp file, at line 17.

Now, run the following, and execute the output binaries for arp_spoof:

```
make arp_spoof && ./arp_spoof
```

Then, run the mallory, and execute the output binaries for mallory:

```
make mallory && ./mallory
```

then run the usual server and after server starts, run the client.

```
make && ./server && ./client
```

> if you want to run this on docker, docker-compose.yml file is provided.
> just copy it in current folder, and run.
> uncomment the mallory service code in docker compose file for testing MITM.
> use `client` and `client2` for 2 different clients, because ip is hardcoded, so running
> again same container will throw address used error.

## How the server proves who it is

When a client connects, the two sides set up a shared secret using a
Diffie-Hellman key exchange. The client sends its public value, and the server
replies with three things:

1. Its own public value.
2. Its certificate (which was signed by the CA).
3. A signature over both public values, made using the server's private key.

The client then does two checks:

- certificate actually signed by CA, and is it for the server (`chat-server`in our case). This confirms the certificate is genuine.
- Does the signature match, using the public key inside that certificate.

The second check is the important one. Only someone who holds the matching
private key can produce a valid signature. The certificate is public, so anyone
can copy it, but no one can fake the signature without the private key. So a
valid signature proves the server actually owns the certificate it presented.

If either check fails, the client refuses to continue.

## Man-in-the-middle attack fails

Mallory sits between the client and the server and tries to relay the traffic.
Mallory can copy and present the real server's certificate, but it does not have
the server's private key, so it cannot produce a valid signature. The client
notices the bad signature and drops the connection.

Mallory:

```
mallory-1  | g++ -o mallory mallory.cpp utils.cpp crypto.cpp -lssl -lcrypto
mallory-1  | g++ -o arp_spoof arp_spoof.cpp
mallory-1  | ARP spoofing started...
mallory-1  | Mallory MITM listening on port 8000
mallory-1  |
mallory-1  | Client connection intercepted.
mallory-1  | Connected to real server.
mallory-1  | Mallory-Client fingerprint = a62d0dc565b25990
mallory-1  | [Mallory] Server-side fingerprint = 8ed91da8c7dcc51e
mallory-1  | MITM interception established.
```

Server:

```
server-1   | Server is running...
server-1   | New client connected. Handshake not done yet...
server-1   | Client 1 connected, fingerprint = 8ed91da8c7dcc51e
```

Client:

```
Connected to server!
Server signature invalid.
Server connection rejected (bad handshake).
Server handshake validation failed...
```

Mallory manages to set up its two separate connections, but the moment the
client checks the signature it sees it is invalid and rejects the connection.
The attack fails.
