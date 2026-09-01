#include "constants.h"
#include "structs.h"
#include "utils.h"
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_set>

using namespace std;

char buffer[MAX_BUFFER_SIZE];

void send_message(int fd, string message) {
  send(fd, message.c_str(), message.size(), 0);
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
    return -1;
  }

  // Start listening
  if (listen(server_fd, 5) == -1) {
    // TODO: free up socket connection
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

void handle_server_input(int server_fd, unordered_set<Client *> &clients) {

  int new_client = accept(server_fd, nullptr, nullptr);

  if (new_client != -1) {

    Client *c = new Client();
    c->fd = new_client;
    clients.insert(c);

    cout << "New client connected." << endl;
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

      string message = client->input_buffer.substr(0, newline_pos);
      trim(message);
      client->input_buffer.erase(0, newline_pos + 1);

      if (message.substr(0, 9) == "REGISTER|") {

        string username = message.substr(9);
        trim(username);
        if (!check_username_available(clients, username)) {
          send_message(client->fd, "ERROR|Username unavailable\n");
        } else {
          client->username = username;
          cout << "Registered: " << username << endl;
          send_message(client->fd, "WELCOME|" + username + "\n");
        }
      } else if (message == "LIST") {
        if (client->username.empty()) {
          // ask user to register
          send_message(client->fd, "ERROR|Not registered...\n");
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
        response.append("\n");

        send_message(client->fd, response);
      } else if (message == "QUIT") {
        dead_clients.insert(client);
        break;
      } else if (message.find("CHAT|", 0) == 0) {
        if (client->username.empty()) {
          // ask user to register
          send_message(client->fd, "ERROR|Not registered...\n");
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
          send_message(client->fd, "ERROR|Target username not specified...\n");
          continue;
        }
        string text = message.substr(second_sep + 1);
        trim(text);

        cout << "Message from ->" << client->username << " -> to -> " << target
             << " -> " << ": " << text << endl;

        if (client->username == target)
          continue;

        bool delivered = false;
        for (auto u : clients) {
          if (u->username == target) {
            string outgoing_msg =
                "FROM|" + client->username + "|" + text + "\n";
            send_message(u->fd, outgoing_msg);
            delivered = true;
            break;
          }
        }
        if (!delivered) {
          send_message(client->fd, "ERROR|User not online\n");
        }
      }
    }
  }

  for (auto client : dead_clients) {
    string username = client->username;
    close(client->fd);
    clients.erase(client);
    delete client;
    cout << username << " disconnected." << endl;
  }
}

int main() {

  int server_fd = create_server();
  if (server_fd < 0) {
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

  close(server_fd);

  return 0;
}
