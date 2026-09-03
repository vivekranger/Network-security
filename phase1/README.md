# Phase 1 - Plaintext Chat


## Command from various server & client VM to run the chat application

Start the server:
./server

Start each client:
./client

## Commands available in the chat application to navigate it.

@username message : Send a message directly to a user.

 /chat username : Select a user for chatting.

 /who : List connected users.

 /quit : Disconnect from the server.

## Message Framing Scheme.

Messages are newline-delimited. Each complete message ends with
the newline character '\n'. The receiver reads data until '\n'
is found, which marks the end of one message.
