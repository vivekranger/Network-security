#include "constants.h"
#include "crypto.h"
#include "utils.h"
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace std;

const int MALLORY_PORT = 8000;

BIGNUM *P;
BIGNUM *G;

// Send the complete message.
bool send_all(int fd, const string &message) {
  size_t total_sent = 0;
  while (total_sent < message.size()) {
    int bytes_sent =
        send(fd, message.data() + total_sent, message.size() - total_sent, 0);
    if (bytes_sent <= 0)
      return false;
    total_sent += bytes_sent;
  }
  return true;
}

// receive one newline-terminated message
bool receive_line(int fd, string &buffer, string &line) {
  while (true) {
    size_t newline_pos = buffer.find('\n');
    if (newline_pos != string::npos) {
      line = buffer.substr(0, newline_pos);
      buffer.erase(0, newline_pos + 1);
      return true;
    }

    char temp[MAX_BUFFER_SIZE];
    int bytes = recv(fd, temp, sizeof(temp), 0);
    if (bytes <= 0)
      return false;
    buffer.append(temp, bytes);
  }
}

bool handshake_with_server(int server_fd, string &buffer, vuc &server_key) {
  BIGNUM *a = random_private(P);
  BIGNUM *A = exp_mod(G, a, P);
  char *Ah = BN_bn2hex(A);
  string Ahex(Ah);
  OPENSSL_free(Ah);
  BN_free(A);

  if (!send_all(server_fd, "HANDSHAKE|" + Ahex + "\n")) {
    BN_free(a);
    return false;
  }

  string line;
  if (!receive_line(server_fd, buffer, line)) {
    BN_free(a);
    return false;
  }

  if (line.substr(0, 10) != "HANDSHAKE|") {
    cout << "Server did not send handshake." << endl;
    BN_free(a);
    return false;
  }

  string payload = line.substr(10);
  size_t p1 = payload.find('|');
  size_t p2 = payload.find('|', p1 + 1);
  if (p1 == string::npos || p2 == string::npos) {
    BN_free(a);
    return false;
  }

  string server_pub = payload.substr(0, p1);
  string cert_pem = b64dec(payload.substr(p1 + 1, p2 - p1 - 1));
  string sig = b64dec(payload.substr(p2 + 1));

  EVP_PKEY *pub = verify_cert(cert_pem, "certs/ca.crt", "chat-server");
  if (!pub) {
    cout << "Server certificate not trusted." << endl;
    BN_free(a);
    return false;
  }
  bool sig_valid = verify_sig(pub, Ahex + "|" + server_pub, sig);
  EVP_PKEY_free(pub);
  if (!sig_valid) {
    cout << "Server signature invalid." << endl;
    BN_free(a);
    return false;
  }

  if (server_pub.size() != KEY_SIZE * 2) {
    BN_free(a);
    return false;
  }

  BIGNUM *B = NULL;
  if (BN_hex2bn(&B, server_pub.c_str()) != server_pub.size() ||
      !valid_public(B, P)) {
    BN_free(a);
    BN_free(B);
    return false;
  }

  BIGNUM *s = exp_mod(B, a, P);
  vuc secret = to_bytes(s);
  server_key = derive_key(secret);
  OPENSSL_cleanse(secret.data(), secret.size());

  cout << "[Mallory] Server-side fingerprint = " << fingerprint(server_key)
       << endl;

  BN_free(a);
  BN_free(B);
  BN_free(s);
  return true;
}

//
// Mallory acts as the server to the client.
//
// Client sends:
// HANDSHAKE|A
//
// Mallory sends:
// HANDSHAKE|B_m|cert|sig
//
// mallory uses real server certificate (its public)
// but since it doesn't have the private key for signing,
// it will try to use its own key (either issued by ca, or some random key)
// which will fail verification at client side.
bool handshake_with_client(int client_fd, string &buffer, vuc &client_key) {
  string line;
  if (!receive_line(client_fd, buffer, line))
    return false;

  if (line.substr(0, 10) != "HANDSHAKE|") {
    cout << "Client did not send handshake." << endl;
    return false;
  }

  string client_pub = line.substr(10);
  if (client_pub.size() != KEY_SIZE * 2)
    return false;

  BIGNUM *A = NULL;
  if (BN_hex2bn(&A, client_pub.c_str()) != client_pub.size() ||
      !valid_public(A, P)) {
    BN_free(A);
    return false;
  }

  BIGNUM *b = random_private(P);
  BIGNUM *B = exp_mod(G, b, P);
  char *Bh = BN_bn2hex(B);
  string Bhex(Bh);
  OPENSSL_free(Bh);

  string cert_pem = read_file("certs/server.crt");
  string sig = "some-random-key-by-mallory";

  send_all(client_fd, "HANDSHAKE|" + Bhex + "|" + b64enc(cert_pem) + "|" +
                          b64enc(sig) + "\n");

  BIGNUM *s = exp_mod(A, b, P);
  vuc secret = to_bytes(s);
  client_key = derive_key(secret);
  OPENSSL_cleanse(secret.data(), secret.size());

  cout << "Mallory-Client fingerprint = " << fingerprint(client_key)
       << endl;

  BN_free(A);
  BN_free(b);
  BN_free(B);
  BN_free(s);
  return true;
}

void relay(int from_fd, int to_fd, string buffer, vuc from_key, vuc to_key,
           string label) {
  string line;
  while (receive_line(from_fd, buffer, line)) {
    string message;
    try {
      message = decrypt(from_key, b64dec(line));
    } catch (const char *err) {
      cout << "Mallory decryption error: " << err << endl;
      break;
    } catch (...) {
      cout << "Mallory unknown error while decryption." << endl;
      break;
    }

    // if this is printing, mallory can read plain text messages
    cout << label << message << endl;

    string outgoing = b64enc(encrypt(to_key, message));
    outgoing.push_back('\n');
    if (!send_all(to_fd, outgoing))
      break;
  }
}

int connect_to_server() {
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd == -1)
    return -1;

  sockaddr_in server_addr{};
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(SERVER_PORT);
  inet_pton(AF_INET, SERVER_HOST, &server_addr.sin_addr);

  if (connect(server_fd, (struct sockaddr *)&server_addr,
              sizeof(server_addr)) == -1) {
    close(server_fd);
    return -1;
  }
  return server_fd;
}

int create_listener() {
  int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd == -1)
    return -1;

  int option = 1;
  setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

  sockaddr_in mallory_addr{};
  mallory_addr.sin_family = AF_INET;
  mallory_addr.sin_port = htons(MALLORY_PORT);
  mallory_addr.sin_addr.s_addr = INADDR_ANY;

  if (::bind(listen_fd, (struct sockaddr *)&mallory_addr,
             sizeof(mallory_addr)) == -1) {
    close(listen_fd);
    return -1;
  }

  if (listen(listen_fd, 5) == -1) {
    close(listen_fd);
    return -1;
  }
  return listen_fd;
}

int main() {
  int listen_fd = create_listener();
  if (listen_fd < 0) {
    cout << "Failed to start Mallory listener..." << endl;
    return -1;
  }

  P = BN_new();
  BN_hex2bn(&P, P_HEX);
  G = BN_new();
  BN_set_word(G, 2);

  cout << "Mallory MITM listening on port " << MALLORY_PORT << endl;

  while (true) {
    int client_fd = accept(listen_fd, nullptr, nullptr);
    if (client_fd == -1)
      continue;

    cout << "\nClient connection intercepted." << endl;

    // connect to the real server
    int server_fd = connect_to_server();
    if (server_fd < 0) {
      cout << "Could not connect to real server." << endl;
      close(client_fd);
      continue;
    }
    cout << "Connected to real server." << endl;

    // client_key -> client - mallory
    // server_key -> server - mallory
    string client_buffer, server_buffer;
    vuc client_key, server_key;

    if (!handshake_with_client(client_fd, client_buffer, client_key)) {
      cout << "Client handshake failed." << endl;
      close(client_fd);
      close(server_fd);
      continue;
    }

    if (!handshake_with_server(server_fd, server_buffer, server_key)) {
      cout << "Server handshake failed." << endl;
      close(client_fd);
      close(server_fd);
      continue;
    }

    cout << "MITM interception established." << endl;

    // two independent encrypted channels
    thread client_to_server(relay, client_fd, server_fd, client_buffer,
                            client_key, server_key, "[CLIENT -> SERVER] ");
    thread server_to_client(relay, server_fd, client_fd, server_buffer,
                            server_key, client_key, "[SERVER -> CLIENT] ");

    client_to_server.join();
    server_to_client.join();

    shutdown(client_fd, SHUT_RDWR);
    shutdown(server_fd, SHUT_RDWR);
    close(client_fd);
    close(server_fd);

    cout << "Connection closed." << endl;
  }

  BN_free(P);
  BN_free(G);
  close(listen_fd);
  return 0;
}
