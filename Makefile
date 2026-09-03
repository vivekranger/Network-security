all: client server
client: client.cpp utils.cpp crypto.cpp
	g++ -o $@ $^ -lssl -lcrypto
server: server.cpp utils.cpp crypto.cpp
	g++ -o $@ $^ -lssl -lcrypto