# Phase 4 — Key Auto-Rotation

The E2E key between two clients is renegotiated every 60 seconds while the
session is alive.

- Every rotation runs a fresh DH exchange, so the new key is different from the
  old one (watch the fingerprint change below).
- Old key is dropped once the new one is ready.
- Chat is not interrupted during a rotation.
- If both sides rotate at the same time, the one with the smaller username keeps
  its handshake and the other answers it, so both end up on the same key.

## Sample run

### Client 1

```
Connected to server!
Handshake successful... Fingerprint = ed26da83fad497ce

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
[16:44:46] E2E session with bob ready, fingerprint = ab90aa4ac9240d09
[16:45:46] E2E session with bob ready, fingerprint = 007ab40fc3d11b7a
[16:46:46] E2E session with bob ready, fingerprint = a85bba9357bf0f90
[16:47:46] E2E session with bob ready, fingerprint = 2dfacfbedc0a6620
[16:48:46] E2E session with bob ready, fingerprint = 367ad15eec0889f8
[16:49:46] E2E session with bob ready, fingerprint = 18139d64ca3c0e5f
```

### Client 2

```
Connected to server!
Handshake successful... Fingerprint = 4e39e0c7074fe64a

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
[16:44:46] E2E session with alice ready, fingerprint = ab90aa4ac9240d09
[16:45:46] E2E session with alice ready, fingerprint = 007ab40fc3d11b7a
[16:46:46] E2E session with alice ready, fingerprint = a85bba9357bf0f90
[16:47:46] E2E session with alice ready, fingerprint = 2dfacfbedc0a6620
[16:48:46] E2E session with alice ready, fingerprint = 367ad15eec0889f8
[16:49:46] E2E session with alice ready, fingerprint = 18139d64ca3c0e5f
```

### Server

```
server-1  | Server is running...
server-1  | New client connected. Handshake not done yet...
server-1  | Client 1 connected, fingerprint = ed26da83fad497ce
server-1  | New client connected. Handshake not done yet...
server-1  | Client 2 connected, fingerprint = 4e39e0c7074fe64a
server-1  | Registered: bob
server-1  | Registered: alice
server-1  | Message from ->bob -> to -> alice -> : hello alice
server-1  | Message from ->bob -> to -> alice -> : __E2E_INIT__9CB4710E...
server-1  | Message from ->alice -> to -> bob -> : __E2E_ACK__91B1FB05...
server-1  | Message from ->bob -> to -> alice -> : __E2E_INIT__C2489802...
server-1  | Message from ->alice -> to -> bob -> : __E2E_INIT__9C4330EE...
server-1  | Message from ->bob -> to -> alice -> : __E2E_ACK__4D8625AD...
```
