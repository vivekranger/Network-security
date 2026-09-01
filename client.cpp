#include "constants.h"
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

void show_help();
void send_message(int client_fd, string message);
string register_user(int client_fd);

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
    send_message(client_fd, "QUIT\n");
    return 0;
  } else if (input == "/list") {
    // /who
    // know the username of active user
    send_message(client_fd, "LIST\n");
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
    // send current message to a particular user
    size_t space_pos = input.find(' ');

    if (space_pos == string::npos) {
      cout << "Usage: @username message" << endl;
      return 1;
    }

    string user_str = input.substr(1, space_pos - 1);
    string text = input.substr(space_pos + 1);
    trim(text);
    send_message(client_fd, "CHAT|" + user_str + "|" + text + "\n");
  } else {
    // normal chat message
    if (current_user.empty()) {
      cout << "No user selected..." << endl;
      show_help();
      return 1;
    }

    send_message(client_fd, "CHAT|" + recipient_user + "|" + input + "\n");
  }

  return 1;
}

bool handle_socket_input(int client_fd, string &current_user,
                         string &recipient_user) {

  char buffer[1024];

  int bytes_recd = recv(client_fd, buffer, sizeof(buffer) - 1, 0);

  if (bytes_recd <= 0) {

    cout << "Server disconnected." << endl;
    return 0;
  }

  buffer[bytes_recd] = '\0';

  string message(buffer);
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

  return 1;
}

string register_user(int client_fd) {
  string username;

  cout << "Enter username: ";
  getline(cin, username);

  string registration_msg = "REGISTER|" + username + "\n";
  send_message(client_fd, registration_msg);
  return username;
}

void send_message(int client_fd, string message) {
  send(client_fd, message.c_str(), message.size(), 0);
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

  close(client_fd);

  return 0;
}

void show_help() {
  cout << "\nCommands:\n"
       << "  /list              list online users\n"
       << "  /chat <username>  set recipient for following messages\n"
       << "  @<username> <msg> send one message to that user\n"
       << "  /quit             exit\n"
       << "  <msg>             send to current recipient (/chat first)\n\n";
}