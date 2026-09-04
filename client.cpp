#include "constants.h"
#include "crypto.h"
#include "utils.h"
#include <arpa/inet.h>
#include <cstring>
#include <ctime>
#include <iostream>
#include <map>
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
string Ahex;

EVP_PKEY *my_key = 0;
string my_cert_pem;
string my_name;
struct Peer {
  vuc key;
  vuc prevkey;
  bool ready = false;
  BIGNUM *eph = 0;
  string mypub;
  string pending;
  time_t last_rekey = 0;
};
map<string, Peer> peers;

const int REKEY_INTERVAL = 60;

void show_help();
void send_message(int client_fd, string message, bool enc = 1);
string register_user(int client_fd);
// handshake
void init_handshake(int client_fd);
bool validate_handshake(int client_fd);
bool verify_handshake(string &server_pub);
// e2e
void send_chat(int client_fd, const string &peer, const string &text);
void e2e_init(int client_fd, const string &peer);
void e2e_recv(int client_fd, const string &sender, const string &type,
              const string &data);
void check_rekey(int client_fd);

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
  if (!getline(cin, input))
    return 0;
  trim(input);
  if (input.empty())
    return 1;

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
  } else if (input.find("/e2e ", 0) == 0) {
    // /e2e username
    // start an end-to-end encrypted session with that user

    if (current_user.empty()) {
      cout << "Please register yourself first....\n";
      current_user = register_user(client_fd);
      return 1;
    }

    string peer = input.substr(5);
    trim(peer);
    if (peer.empty()) {
      show_help();
      return 1;
    }

    recipient_user = peer;
    e2e_init(client_fd, peer);
    cout << "Starting E2E session with `" << peer << "`" << endl;
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
    send_chat(client_fd, recipient_user, text);
  } else {
    // normal chat message
    if (current_user.empty()) {
      cout << "No user selected..." << endl;
      show_help();
      return 1;
    }

    send_chat(client_fd, recipient_user, input);
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

    string message;
    try {
      message = decrypt(server.key, b64dec(enc_message));
    } catch (const char *err) {
      cout << "decryption error: " << err << endl;
      return 0;
    } catch (...) {
      cout << "unknown error while decryption." << endl;
      return 0;
    }

    if (message.rfind("WELCOME|", 0) == 0) {
      cout << "Username registered." << endl;
    } else if (message.rfind("USERS|", 0) == 0) {

      string users = message.substr(6);
      cout << "Online users: " << users << endl;
    } else if (message.rfind("FROM|", 0) == 0) {

      size_t first_sep = message.find('|');
      size_t second_sep = message.find('|', first_sep + 1);
      string sender = message.substr(first_sep + 1, second_sep - first_sep - 1);
      string text = message.substr(second_sep + 1);

      if (text.rfind("__E2E_INIT__", 0) == 0)
        e2e_recv(client_fd, sender, "INIT", text.substr(12));
      else if (text.rfind("__E2E_ACK__", 0) == 0)
        e2e_recv(client_fd, sender, "ACK", text.substr(11));
      else if (text.rfind("__E2E_MSG__", 0) == 0)
        e2e_recv(client_fd, sender, "MSG", text.substr(11));
      else
        cout << sender << ": " << text << endl;
    } else if (message.rfind("ERROR|", 0) == 0) {
      cout << "Error: " << message.substr(6)<< endl;
    }
  }

  return 1;
}

string register_user(int client_fd) {
  string username;

  cout << "Enter username: ";
  getline(cin, username);

  my_key = load_privkey("certs/" + username + ".key");
  my_cert_pem = read_file("certs/" + username + ".crt");
  my_name = username;

  send_message(client_fd, "REGISTER|" + username);
  return username;
}

void send_message(int client_fd, string message, bool enc) {
  string msg;
  if (enc)
    msg = b64enc(encrypt(server.key, message));
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

  // Wait for keyboard or server, wake up every second to check rekey timer
  timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  int activity = select(max_fd + 1, read_fds, nullptr, nullptr, &tv);

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
    bool active = check_activity(client_fd, &read_fds);

    // rotate any stale keys before handling activity
    check_rekey(client_fd);

    // No activity occured either in socket or client
    if (!active)
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
       << "  /who              list online users\n"
       << "  /chat <username>  set recipient for following messages\n"
       << "  /e2e <username>   start an end-to-end encrypted session\n"
       << "  @<username> <msg> set recipient for following messages and send "
          "message \n"
       << "  /quit             exit\n"
       << "  <msg>             send to current recipient (/chat first)\n\n";
}

void init_handshake(int client_fd) {
  BIGNUM *a = random_private(P);
  BIGNUM *A = exp_mod(G, a, P);
  char *Ah = BN_bn2hex(A);
  Ahex = string(Ah);
  OPENSSL_free(Ah);

  // client sends handshaking first;
  send_message(client_fd, "HANDSHAKE|" + string(Ahex), 0);
  temp_a = a;
  BN_free(A);
}

bool verify_handshake(string &server_payload) {
  size_t p1 = server_payload.find('|');
  if (p1 == string::npos)
    return false;
  size_t p2 = server_payload.find('|', p1 + 1);
  if (p2 == string::npos)
    return false;

  string server_pub = server_payload.substr(0, p1);
  string cert_pem = b64dec(server_payload.substr(p1 + 1, p2 - p1 - 1));
  string sig = b64dec(server_payload.substr(p2 + 1));

  EVP_PKEY *pub = verify_cert(cert_pem, "certs/ca.crt", "chat-server");
  if (!pub) {
    cout << "Server certificate not trusted." << endl;
    return false;
  }
  bool sig_valid = verify_sig(pub, string(Ahex) + "|" + server_pub, sig);
  EVP_PKEY_free(pub);
  if (!sig_valid) {
    cout << "Server signature invalid." << endl;
    return false;
  }

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
  while (!server.ready) {
    FD_ZERO(&read_fds);
    FD_SET(client_fd, &read_fds);
    int max_fd = client_fd;
    int activity = select(max_fd + 1, &read_fds, nullptr, nullptr, nullptr);
    if (activity <= 0)
      continue;
    string s;
    if (!handle_socket_input(client_fd, s, s))
      return false;
  }

  return true;
}

void send_chat(int client_fd, const string &peer, const string &text) {
  if (peer.empty()) {
    cout << "No recipient selected..." << endl;
    return;
  }

  Peer &p = peers[peer];
  if (p.ready) {
    send_message(client_fd,
                 "CHAT|" + peer + "|__E2E_MSG__" + b64enc(encrypt(p.key, text)));
  } else if (p.eph != 0) {
    cout << "E2E session with `" << peer << "` not ready yet..." << endl;
  } else {
    send_message(client_fd, "CHAT|" + peer + "|" + text);
  }
}

string now_str() {
  time_t t = time(0);
  char buf[16];
  strftime(buf, sizeof(buf), "%H:%M:%S", localtime(&t));
  return string(buf);
}

void check_rekey(int client_fd) {
  time_t now = time(0);
  for (auto &it : peers) {
    Peer &p = it.second;
    // only rotate live sessions that are not already mid handshake
    if (p.ready && p.eph == 0 && now - p.last_rekey >= REKEY_INTERVAL)
      e2e_init(client_fd, it.first);
  }
}

void e2e_init(int client_fd, const string &peer) {
  if (!my_key || my_cert_pem.empty()) {
    cout << "No certificate loaded for user `" << my_name << "`." << endl;
    return;
  }

  BIGNUM *a = random_private(P);
  BIGNUM *A = exp_mod(G, a, P);
  char *Ah = BN_bn2hex(A);
  string Apub(Ah);
  OPENSSL_free(Ah);
  BN_free(A);

  Peer &p = peers[peer];
  if (p.eph)
    BN_free(p.eph);
  p.eph = a;
  p.mypub = Apub;
  // keep p.ready/p.key as is so chat keeps working while we renegotiate

  string sig = sign_data(my_key, Apub);
  send_message(client_fd, "CHAT|" + peer + "|__E2E_INIT__" + Apub + "|" +
                              b64enc(my_cert_pem) + "|" + b64enc(sig));
}

void e2e_recv(int client_fd, const string &sender, const string &type,
              const string &data) {
  if (type == "MSG") {
    Peer &p = peers[sender];
    if (!p.ready) {
      cout << "E2E message from " << sender << " but no session." << endl;
      return;
    }
    try {
      string text = decrypt(p.key, b64dec(data));
      cout << sender << ": " << text << endl;
    } catch (...) {
      // might be a message still encrypted with the key from before a rotation
      if (!p.prevkey.empty()) {
        try {
          string text = decrypt(p.prevkey, b64dec(data));
          cout << sender << ": " << text << endl;
          return;
        } catch (...) {
        }
      }
      cout << "E2E decryption failed from " << sender << endl;
    }
    return;
  }

  if (type == "INIT") {
    if (!my_key || my_cert_pem.empty())
      return;

    // both sides fired a renegotiation at the same time.
    if (peers[sender].eph != 0 && my_name < sender)
      return;

    size_t p1 = data.find('|');
    if (p1 == string::npos)
      return;
    size_t p2 = data.find('|', p1 + 1);
    if (p2 == string::npos)
      return;

    string Apub = data.substr(0, p1);
    string cert_pem = b64dec(data.substr(p1 + 1, p2 - p1 - 1));
    string sig = b64dec(data.substr(p2 + 1));

    EVP_PKEY *pub = verify_cert(cert_pem, "certs/ca.crt", sender);
    if (!pub) {
      cout << "Peer certificate not trusted." << endl;
      return;
    }
    bool sig_valid = verify_sig(pub, Apub, sig);
    EVP_PKEY_free(pub);
    if (!sig_valid) {
      cout << "Peer signature invalid." << endl;
      return;
    }

    if (Apub.size() != KEY_SIZE * 2)
      return;

    BIGNUM *A = NULL;
    if (BN_hex2bn(&A, Apub.c_str()) != Apub.size()) {
      BN_free(A);
      return;
    }
    if (!valid_public(A, P)) {
      BN_free(A);
      return;
    }

    BIGNUM *b = random_private(P);
    BIGNUM *B = exp_mod(G, b, P);
    char *Bh = BN_bn2hex(B);
    string Bpub(Bh);
    OPENSSL_free(Bh);

    string sig2 = sign_data(my_key, Apub + "|" + Bpub);
    send_message(client_fd, "CHAT|" + sender + "|__E2E_ACK__" + Bpub + "|" +
                                b64enc(my_cert_pem) + "|" + b64enc(sig2));

    BIGNUM *secret_num = exp_mod(A, b, P);
    vuc secret = to_bytes(secret_num);

    Peer &p = peers[sender];
    if (p.eph) {
      BN_free(p.eph);
      p.eph = 0;
    }
    if (!p.prevkey.empty())
      OPENSSL_cleanse(p.prevkey.data(), p.prevkey.size());
    p.prevkey = p.key;
    p.key = derive_key(secret);
    p.ready = true;
    p.last_rekey = time(0);
    OPENSSL_cleanse(secret.data(), secret.size());

    cout << "[" << now_str() << "] E2E session with " << sender
         << " ready, fingerprint = " << fingerprint(p.key) << endl;

    BN_free(A);
    BN_free(B);
    BN_free(b);
    BN_free(secret_num);
    return;
  }

  if (type == "ACK") {
    Peer &p = peers[sender];
    if (p.eph == 0)
      return;

    size_t p1 = data.find('|');
    if (p1 == string::npos)
      return;
    size_t p2 = data.find('|', p1 + 1);
    if (p2 == string::npos)
      return;

    string Bpub = data.substr(0, p1);
    string cert_pem = b64dec(data.substr(p1 + 1, p2 - p1 - 1));
    string sig = b64dec(data.substr(p2 + 1));

    EVP_PKEY *pub = verify_cert(cert_pem, "certs/ca.crt", sender);
    if (!pub) {
      cout << "Peer certificate not trusted." << endl;
      return;
    }
    bool sig_valid = verify_sig(pub, p.mypub + "|" + Bpub, sig);
    EVP_PKEY_free(pub);
    if (!sig_valid) {
      cout << "Peer signature invalid." << endl;
      return;
    }

    if (Bpub.size() != KEY_SIZE * 2)
      return;

    BIGNUM *B = NULL;
    if (BN_hex2bn(&B, Bpub.c_str()) != Bpub.size()) {
      BN_free(B);
      return;
    }
    if (!valid_public(B, P)) {
      BN_free(B);
      return;
    }

    BIGNUM *secret_num = exp_mod(B, p.eph, P);
    vuc secret = to_bytes(secret_num);
    if (!p.prevkey.empty())
      OPENSSL_cleanse(p.prevkey.data(), p.prevkey.size());
    p.prevkey = p.key;
    p.key = derive_key(secret);
    p.ready = true;
    p.last_rekey = time(0);
    OPENSSL_cleanse(secret.data(), secret.size());
    BN_free(p.eph);
    p.eph = 0;

    cout << "[" << now_str() << "] E2E session with " << sender
         << " ready, fingerprint = " << fingerprint(p.key) << endl;

    BN_free(B);
    BN_free(secret_num);
    return;
  }
}
