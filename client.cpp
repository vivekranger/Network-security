#include "constants.h"
#include "crypto.h"
#include "utils.h"
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;

string buffer;
struct ServerConn {
  int fd;
  vuc key;
  bool ready = false;
} server;

BIGNUM *P;
BIGNUM *G;
BIGNUM *temp_a = 0;

void show_help();
void send_message(int client_fd, string message, bool enc = 1);
string register_user(int client_fd);
// handshake
void init_handshake(int client_fd);
bool validate_handshake(int client_fd);
bool verify_handshake(string &server_pub);

int connect_to_server() {
  int client_fd = socket(AF_INET, SOCK_STREAM, 0);

  if (client_fd == -1)
    return -1;

  sockaddr_in server_addr{};
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(SERVER_PORT);

  // Server IP address
  inet_pton(AF_INET, SERVER_HOST, &server_addr.sin_addr);

  // Connect to server
  if (connect(client_fd, (struct sockaddr *)&server_addr,
              sizeof(server_addr)) == -1)
    return -1;

  cout << "Connected to server!" << endl;

  return client_fd;
}

bool handle_kb_input(int client_fd, string &current_user,
                     string &recipient_user) {
  string input;
  getline(cin, input);
  trim(input);

  if (input == "/quit") {
    // /quit
    // quit the chat app
    send_message(client_fd, "QUIT");
    return 0;
  } else if (input == "/who") {
    // /who
    // know the username of active user
    send_message(client_fd, "WHO");
  } else if (input.find("/chat ", 0) == 0) {
    // /chat username
    // to fix a recipient user, so all following messages will go to that user

    if (current_user.empty()) {
      cout << "Please register yourself first....\n";
      current_user = register_user(client_fd);
      return 1;
    }

    recipient_user = input.substr(6);
    trim(recipient_user);
    if (recipient_user.empty()) {
      show_help();
      return 1;
    }

    cout << "Now chatting with `" << recipient_user << "`" << endl;
  } else if (!input.empty() && input[0] == '@') {
    // @username message
    // send current message to a particular user, and make that user receipient
    size_t space_pos = input.find(' ');

    if (space_pos == string::npos) {
      cout << "Usage: @username message" << endl;
      return 1;
    }

    string user_str = input.substr(1, space_pos - 1);
    recipient_user = user_str;
    string text = input.substr(space_pos + 1);
    trim(text);
    send_message(client_fd, "CHAT|" + recipient_user + "|" + text);
  } else {
    // normal chat message
    if (current_user.empty()) {
      cout << "No user selected..." << endl;
      show_help();
      return 1;
    }

    send_message(client_fd, "CHAT|" + recipient_user + "|" + input);
  }

  return 1;
}

bool handle_socket_input(int client_fd, string &current_user,
                         string &recipient_user) {
  char buf[1024];
  int bytes_recd = recv(client_fd, buf, sizeof(buf), 0);
  if (bytes_recd <= 0) {
    cout << "Server disconnected." << endl;
    return 0;
  }

  buffer.append(buf, bytes_recd);

  size_t newline_pos;
  while ((newline_pos = buffer.find('\n')) != string::npos) {

    string enc_message = buffer.substr(0, newline_pos);
    buffer.erase(0, newline_pos + 1);

    // string enc_message(buffer);

    if (!server.ready) {
      bool hs_valid = false;
      if (enc_message.substr(0, 10) == "HANDSHAKE|") {
        string str = enc_message.substr(10);
        trim(str);
        hs_valid = verify_handshake(str);
      }

      if (!hs_valid) {
        cout << "Server connection rejected (bad handshake)." << endl;
        buffer.clear();
        return 0;
      }
      server.ready = true;
      continue;
    }

    string message = decrypt(server.key, enc_message);
    if (message.rfind("WELCOME|", 0) == 0) {
      cout << "Username registered." << endl;
    } else if (message.rfind("USERS|", 0) == 0) {

      string users = message.substr(6);
      cout << "Online users: " << users;
    } else if (message.rfind("FROM|", 0) == 0) {

      size_t first_sep = message.find('|');
      size_t second_sep = message.find('|', first_sep + 1);
      string sender = message.substr(first_sep + 1, second_sep - first_sep - 1);
      string text = message.substr(second_sep + 1);

      cout << sender << ": " << text;
    } else if (message.rfind("ERROR|", 0) == 0) {
      cout << "Error: " << message.substr(6);
    }
  }

  return 1;
}

string register_user(int client_fd) {
  string username;

  cout << "Enter username: ";
  getline(cin, username);

  send_message(client_fd, "REGISTER|" + username);
  return username;
}

void send_message(int client_fd, string message, bool enc) {
  string msg;
  if (enc)
    msg = encrypt(server.key, message);
  else
    msg = message;
  msg.push_back('\n');
  send(client_fd, msg.c_str(), msg.size(), 0);
}

bool check_activity(int client_fd, fd_set *read_fds) {
  FD_ZERO(read_fds);

  // Watch keyboard
  FD_SET(STDIN_FILENO, read_fds);

  // Watch server
  FD_SET(client_fd, read_fds);

  int max_fd = client_fd;

  // Wait for keyboard or server
  int activity = select(max_fd + 1, read_fds, nullptr, nullptr, nullptr);

  return activity > 0;
}

int main() {

  // connect to server
  int client_fd = connect_to_server();
  if (client_fd < 0) {
    cout << "Failed to connect to server...";
    return 0;
  }

  P = BN_new();
  BN_hex2bn(&P, P_HEX);
  G = BN_new();
  BN_set_word(G, 2);

  init_handshake(client_fd);
  if (!validate_handshake(client_fd)) {
    cout << "Server handshake validation failed..." << endl;
    BN_free(P);
    BN_free(G);
    close(client_fd);
    return 0;
  }

  cout << "Handshake successful... Fingerprint = " << fingerprint(server.key)
       << endl;

  show_help();

  // Register and set user active
  string current_user = register_user(client_fd);
  string recipient_user;

  fd_set read_fds;

  while (true) {
    // No activity occured either in socket or client
    if (!check_activity(client_fd, &read_fds))
      continue;

    // Check keyboard
    if (FD_ISSET(STDIN_FILENO, &read_fds) &&
        !handle_kb_input(client_fd, current_user, recipient_user))
      break;

    // Check server
    if (FD_ISSET(client_fd, &read_fds) &&
        !handle_socket_input(client_fd, current_user, recipient_user))
      break;
  }

  BN_free(P);
  BN_free(G);
  close(client_fd);

  return 0;
}

void show_help() {
  cout << "\nCommands:\n"
       << "  /list              list online users\n"
       << "  /chat <username>  set recipient for following messages\n"
       << "  @<username> <msg> set recipient for following messages and send "
          "message \n"
       << "  /quit             exit\n"
       << "  <msg>             send to current recipient (/chat first)\n\n";
}

void init_handshake(int client_fd) {
  BIGNUM *a = random_private(P);
  BIGNUM *A = exp_mod(G, a, P);

  // client sends handshaking first;
  string msg_str = "HANDSHAKE|" + string(BN_bn2hex(A));
  send_message(client_fd, msg_str, 0);
  temp_a = a;
  BN_free(A);
}

bool verify_handshake(string &server_pub) {
  if (server_pub.size() != KEY_SIZE * 2) // client_pub is in hex
    return false;

  BIGNUM *B = NULL;
  if (BN_hex2bn(&B, server_pub.c_str()) != server_pub.size()) {
    // some issue in hex string
    BN_free(B);
    return 0;
  }
  if (!valid_public(B, P)) {
    BN_free(B);
    return 0;
  }

  if (temp_a == 0)
    throw "Some Error occured in handshake...";

  BIGNUM *secret_num = exp_mod(B, temp_a, P);
  vuc secret = to_bytes(secret_num);
  server.key = derive_key(secret);
  OPENSSL_cleanse(secret.data(), secret.size());
  BN_free(temp_a);
  temp_a = 0;
  BN_free(B);
  BN_free(secret_num);
  return true;
}

bool validate_handshake(int client_fd) {
  fd_set read_fds;
  while (true) {
    FD_ZERO(&read_fds);
    FD_SET(client_fd, &read_fds);
    int max_fd = client_fd;
    int activity = select(max_fd + 1, &read_fds, nullptr, nullptr, nullptr);
    string s = "";
    if (activity > 0)
      return handle_socket_input(client_fd, s, s);
  }

  return 0;
}
