all: client server
client: client.cpp utils.cpp
	g++ -o $@ $^
server: server.cpp utils.cpp
	g++ -o $@ $^