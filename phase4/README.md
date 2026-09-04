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
> use `client` and `client2` for 2 different clients, because ip is hardcoded, so running
> again same container will throw address used error.

## End-to-end encrypted mode

two clients set up their own shared key, and the server only
ever relays ciphertext it cannot read.

To generate certificate for a particular <username>, run:

```
make usercert U=<username>
```
then when registering, register with that exact same <username>

To start an E2E session, run:

```
/e2e <username>
```

`/chat <username>` alone sets the recipient but sends in plaintext (the server
can read it); `/e2e <username>` upgrades that conversation to encrypted.

### Example run

client 1 (alice):

```
Connected to server!
Handshake successful... Fingerprint = e555ec4e36dea215

Commands:
  /who              list online users
  /chat <username>  set recipient for following messages
  /e2e <username>   start an end-to-end encrypted session
  @<username> <msg> set recipient for following messages and send message 
  /quit             exit
  <msg>             send to current recipient (/chat first)

Enter username: alice
Username registered.
bob: hello alice
E2E session with bob ready, fingerprint = 1c162d6693c6603a
bob: hello alice, this is secret message
thanks bob
No recipient selected...
/chat bob
Now chatting with `bob`
thanks bob
/e2e bob
Starting E2E session with `bob`
E2E session with bob ready, fingerprint = a63205f13d4af03e
thanks bob 
bob: thanks alice
```

client 2 (bob):

```
Connected to server!
Handshake successful... Fingerprint = 1a6a4e77187e58da

Commands:
  /who              list online users
  /chat <username>  set recipient for following messages
  /e2e <username>   start an end-to-end encrypted session
  @<username> <msg> set recipient for following messages and send message 
  /quit             exit
  <msg>             send to current recipient (/chat first)

Enter username: bob 
Username registered.
/chat alice
Now chatting with `alice`
hello alice
/e2e alice
Starting E2E session with `alice`
E2E session with alice ready, fingerprint = 1c162d6693c6603a
hello alice, this is secret message
alice: thanks bob
E2E session with alice ready, fingerprint = a63205f13d4af03e
alice: thanks bob
thanks alice
```

Server (relays only ciphertext once E2E is active):

```
server-1  | Server is running...
server-1  | New client connected. Handshake not done yet...
server-1  | Client 1 connected, fingerprint = e555ec4e36dea215
server-1  | Registered: alice
server-1  | New client connected. Handshake not done yet...
server-1  | Client 2 connected, fingerprint = 1a6a4e77187e58da
server-1  | Registered: bob
server-1  | Message from ->bob -> to -> alice -> : hello alice
server-1  | Message from ->bob -> to -> alice -> : __E2E_INIT__60BA77...
server-1  | Message from ->alice -> to -> bob -> : __E2E_ACK__EE67EF...
server-1  | Message from ->bob -> to -> alice -> : __E2E_MSG__bSWp57q8gg3R5Po5yGbTY28pB4pHVmtNkL7GcOHYEXn9nKW9hCfeMyiF5rZs3Oi9pp6iqBOorq/26wDuG5Zq
server-1  | Message from ->alice -> to -> bob -> : __E2E_MSG__vRonZhNouORHpUgdxwZXofNqAMj5vC2O0Hq5PYfwe8Sztamoar4=
server-1  | Message from ->alice -> to -> bob -> : __E2E_INIT__0185FA...
server-1  | Message from ->bob -> to -> alice -> : __E2E_ACK__254BB8...
server-1  | Message from ->alice -> to -> bob -> : __E2E_MSG__XS3kGs2tXvztMgBQHQZ3og0zMRhsj8rV7nUyaBS7PE38hkxxWqQ=
server-1  | Message from ->bob -> to -> alice -> : __E2E_MSG__bxRYK+xEzngwRCcsrWeYFcHXh2W13q2FIUAge/KFlwVgqM9sT1dOsg==
```
