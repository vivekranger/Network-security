all: client server certs
client: client.cpp utils.cpp crypto.cpp
	g++ -o $@ $^ -lssl -lcrypto
server: server.cpp utils.cpp crypto.cpp
	g++ -o $@ $^ -lssl -lcrypto

# seperate from all
mallory: mallory.cpp utils.cpp crypto.cpp
	g++ -o $@ $^ -lssl -lcrypto
arp_spoof: arp_spoof.cpp
	g++ -o $@ $^

.PHONY: all certs
certs: certs/server.crt

certs/server.crt: certs/server.ext
	mkdir -p certs
	openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
	  -keyout certs/ca.key -out certs/ca.crt -subj "/CN=cs6008-CA" \
	  -addext "basicConstraints=critical,CA:TRUE" \
	  -addext "keyUsage=critical,keyCertSign,cRLSign"
	openssl req -newkey rsa:2048 -nodes \
	  -keyout certs/server.key -out certs/server.csr -subj "/CN=chat-server"
	openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key \
	  -CAcreateserial -days 365 -extfile certs/server.ext -out certs/server.crt
	openssl verify -CAfile certs/ca.crt certs/server.crt
