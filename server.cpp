#include "constants.h"
#include "crypto.h"
#include "structs.h"
#include "utils.h"
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_set>

using namespace std;

int last_id = 0;
char buffer[MAX_BUFFER_SIZE];
BIGNUM *P;
BIGNUM *G;
EVP_PKEY *srv_key;
string srv_cert_pem;

void send_message(Client *c, string message, bool enc = 1) {
  string msg;
  if (enc && c->ready)
    msg = b64enc(encrypt(c->key, message));
  else
    msg = message;
  msg.push_back('\n');
  send(c->fd, msg.c_str(), msg.size(), 0);
}

bool check_username_available(unordered_set<Client *> &clients,
                              string username) {
  if (username.empty())
    return false;
  // check for any special chars in username
  for (auto client : clients) {
    if (client->username == username)
      return false;
  }
  return true;
}

int create_server() {
  // Create TCP socket
  // AF_INET is for IPv4 and the second argument is to mention byte stream
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);

  if (server_fd == -1)
    return -1;

  sockaddr_in server_addr{}; //

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(SERVER_PORT);
  server_addr.sin_addr.s_addr = INADDR_ANY;

  // Bind socket to port 5000
  if (::bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) ==
      -1) {
    // TODO: free up socket connection
    close(server_fd);
    return -1;
  }

  // Start listening
  if (listen(server_fd, 5) == -1) {
    // TODO: free up socket connection
    close(server_fd);
    return -1;
  }

  cout << "Server is running..." << endl;
  return server_fd;
}

bool check_activity(int server_fd, fd_set *read_fds,
                    unordered_set<Client *> &clients) {
  FD_ZERO(read_fds);

  // Watch server
  FD_SET(server_fd, read_fds);

  int max_fd = server_fd;

  // Watch connected clients
  for (auto client : clients) {
    FD_SET(client->fd, read_fds);
    max_fd = max(max_fd, client->fd);
  }

  int activity = select(max_fd + 1, read_fds, nullptr, nullptr, nullptr);

  return activity > 0;
}

bool handshake(Client *c, string &client_pub) {
  BIGNUM *b = random_private(P);
  BIGNUM *B = exp_mod(G, b, P);

  if (client_pub.size() != KEY_SIZE * 2) // client_pub is in hex
    return false;

  BIGNUM *A = NULL;
  if (BN_hex2bn(&A, client_pub.c_str()) != client_pub.size()) {
    // some issue in hex string
    BN_free(A);
    return 0;
  }
  if (!valid_public(A, P)) {
    BN_free(A);
    return 0;
  }

  char *Bhex = BN_bn2hex(B);
  string Bhex_str(Bhex);
  OPENSSL_free(Bhex);
  string sig = sign_data(srv_key, client_pub + "|" + Bhex_str);

  // HANDSHAKE|DH_key(Gˆb)|srv_cert_pem|sig
  send_message(c,
               "HANDSHAKE|" + Bhex_str + "|" + b64enc(srv_cert_pem) + "|" +
                   b64enc(sig),
               0);

  BIGNUM *s = exp_mod(A, b, P);
  vuc secret = to_bytes(s);
  c->key = derive_key(secret);
  OPENSSL_cleanse(secret.data(), secret.size());
  BN_free(b);
  BN_free(B);
  BN_free(A);
  return true;
}

void handle_server_input(int server_fd, unordered_set<Client *> &clients) {

  int new_client = accept(server_fd, nullptr, nullptr);

  if (new_client != -1) {

    Client *c = new Client();
    c->id = ++last_id;
    c->fd = new_client;
    c->ready = false;
    clients.insert(c);

    cout << "New client connected. Handshake not done yet..." << endl;
  }
}

void handle_socket_input(fd_set *read_fds, unordered_set<Client *> &clients) {
  unordered_set<Client *> dead_clients;
  for (auto client : clients) {
    if (!FD_ISSET(client->fd, read_fds))
      continue;
    int bytes_recd = recv(client->fd, buffer, sizeof(buffer), 0);

    if (bytes_recd <= 0) {
      // client disconnected
      dead_clients.insert(client);
      continue;
    }

    // Process lines which are received fully, maybe some part of line received
    // in following message, hold the received part
    client->input_buffer.append(buffer, bytes_recd);

    size_t newline_pos;
    while ((newline_pos = client->input_buffer.find('\n')) != string::npos) {

      string enc_message = client->input_buffer.substr(0, newline_pos);
      client->input_buffer.erase(0, newline_pos + 1);

      if (!client->ready) {
        // make it blocking for the handshake only
        int flags = fcntl(client->fd, F_GETFL, 0);
        fcntl(client->fd, F_SETFL, flags & ~O_NONBLOCK);
        bool hs_valid = false;
        if (enc_message.substr(0, 10) == "HANDSHAKE|") {
          string s = enc_message.substr(10);
          hs_valid = handshake(client, s);
        }

        if (!hs_valid) {
          cout << "Client " << client->id << " rejected (bad handshake)."
               << endl;
          dead_clients.insert(client);
          break;
        }

        fcntl(client->fd, F_SETFL, flags); // make it non-blocking again
        client->ready = true;

        cout << "Client " << client->id
             << " connected, fingerprint = " << fingerprint(client->key)
             << endl;
      } else {
        string message;
        try {
          message = decrypt(client->key, b64dec(enc_message));
        } catch (const char *err) {
          cout << "decryption error: " << err << endl;
          dead_clients.insert(client);
          break;
        } catch (...) {
          cout << "unknown error while decryption." << endl;
          dead_clients.insert(client);
          break;
        }

        if (message.substr(0, 9) == "REGISTER|") {

          string username = message.substr(9);
          trim(username);
          if (!check_username_available(clients, username)) {
            send_message(client, "ERROR|Username unavailable");
          } else {
            client->username = username;
            cout << "Registered: " << username << endl;
            send_message(client, "WELCOME|" + username);
          }
        } else if (message == "WHO") {
          if (client->username.empty()) {
            // ask user to register
            send_message(client, "ERROR|Not registered...");
            continue;
          }

          // list of online users, comma seperated
          string response = "USERS|";
          for (auto u : clients) {
            if (u->username.empty())
              continue;
            response.append(u->username);
            response.push_back(',');
          }
          // if any user added to list, at last an extra comma will be there
          if (response.back() == ',')
            response.pop_back();

          send_message(client, response);
        } else if (message == "QUIT") {
          dead_clients.insert(client);
          break;
        } else if (message.find("CHAT|", 0) == 0) {
          if (client->username.empty()) {
            // ask user to register
            send_message(client, "ERROR|Not registered...");
            continue;
          }

          size_t first_sep = message.find('|');
          size_t second_sep = message.find('|', first_sep + 1);
          if (second_sep == string::npos) {
            continue;
          }

          string target =
              message.substr(first_sep + 1, second_sep - first_sep - 1);
          trim(target);
          if (target.empty()) {
            send_message(client, "ERROR|Target username not specified...");
            continue;
          }
          string text = message.substr(second_sep + 1);
          trim(text);

          cout << "Message from ->" << client->username << " -> to -> "
               << target << " -> " << ": " << text << endl;

          if (client->username == target)
            continue;

          bool delivered = false;
          for (auto u : clients) {
            if (u->username == target) {
              string outgoing_msg = "FROM|" + client->username + "|" + text;
              send_message(u, outgoing_msg);
              delivered = true;
              break;
            }
          }
          if (!delivered) {
            send_message(client, "ERROR|User not online");
          }
        }
      }
    }
  }

  for (auto client : dead_clients) {
    cout << "Client " << client->id << " disconnected." << endl;
    OPENSSL_cleanse(client->key.data(), client->key.size());
    close(client->fd);
    clients.erase(client);
    delete client;
  }
}

int main() {

  int server_fd = create_server();
  if (server_fd < 0) {
    return -1;
  }

  P = BN_new();
  BN_hex2bn(&P, P_HEX);
  G = BN_new();
  BN_set_word(G, 2);

  srv_key = load_privkey("certs/server.key");
  srv_cert_pem = read_file("certs/server.crt");
  if (!srv_key || srv_cert_pem.empty()) {
    cerr << "missing server.key or server.crt" << endl;
    return -1;
  }

  // mapping from username to client obj
  unordered_set<Client *> clients;

  fd_set read_fds;

  while (true) {

    if (!check_activity(server_fd, &read_fds, clients))
      continue;

    // Check for a new client
    if (FD_ISSET(server_fd, &read_fds)) {
      handle_server_input(server_fd, clients);
    }

    handle_socket_input(&read_fds, clients);
  }

  BN_free(P);
  BN_free(G);
  close(server_fd);

  return 0;
}
