#include <iostream>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <unistd.h>

// This is to ensure that the enitre data pertaining to the client is stored as a structure.
struct Client {
    int fd = -1; // Initially till the time any client is connected, initializing fd as -1
    std::string username;
    std::string input_buffer;
};

void send_message(int fd, const std::string& message) {
    send(fd, message.c_str(), message.size(), 0);
}

int main() {

    // Create TCP socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0); //AF_INET is for IPv4 and the second argument is to mention byte stream

    if (server_fd == -1) {
        return 1;
    }

    sockaddr_in server_addr{}; // 

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(5000);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // Bind socket to port 5000
    if (bind(server_fd,
             (struct sockaddr*)&server_addr,
             sizeof(server_addr)) == -1) {
        return 1;
    }

    // Start listening
    if (listen(server_fd, 5) == -1) {
        return 1;
    }

    std::cout << "Server is running..." << std::endl;

    Client clients[2];

    fd_set read_fds;

    while (true) {

        FD_ZERO(&read_fds);

        // Watch for new clients
        FD_SET(server_fd, &read_fds);

        int max_fd = server_fd;

        // Watch connected clients
        for (int i = 0; i < 2; i++) {

            if (clients[i].fd != -1) {

                FD_SET(clients[i].fd, &read_fds);

                if (clients[i].fd > max_fd) {
                    max_fd = clients[i].fd;
                }
            }
        }

        // Wait for something to happen
        int activity = select(max_fd + 1,
                              &read_fds,
                              nullptr,
                              nullptr,
                              nullptr);

        if (activity == -1) {
            return 1;
        }

        // Check for a new client
        if (FD_ISSET(server_fd, &read_fds)) {

            int new_client = accept(server_fd, nullptr, nullptr);

            if (new_client != -1) {

                int slot = -1;

                for (int i = 0; i < 2; i++) {
                    if (clients[i].fd == -1) {
                        slot = i;
                        break;
                    }
                }

                if (slot != -1) {

                    clients[slot].fd = new_client;

                    std::cout << "New client connected."
                              << std::endl;

                } else {

                    // Already have two clients
                    send_message(new_client,
                                 "ERROR|Server full\n");

                    close(new_client);
                }
            }
        }

        // Check both clients
        for (int i = 0; i < 2; i++) {

            if (clients[i].fd == -1) {
                continue;
            }

            if (!FD_ISSET(clients[i].fd, &read_fds)) {
                continue;
            }

            char buffer[1024];

            int bytes_recd = recv(clients[i].fd,
                                  buffer,
                                  sizeof(buffer),
                                  0);

            if (bytes_recd <= 0) {

                std::cout << clients[i].username
                          << " disconnected."
                          << std::endl;

                close(clients[i].fd);
                clients[i] = Client();

                continue;
            }

            clients[i].input_buffer.append(buffer, bytes_recd);

            // Process complete lines
            size_t newline_pos;

            while ((newline_pos =
                    clients[i].input_buffer.find('\n'))
                    != std::string::npos) {

                std::string message =
                    clients[i].input_buffer.substr(
                        0, newline_pos);

                clients[i].input_buffer.erase(
                    0, newline_pos + 1);

                // -------------------------
                // Register username
                // -------------------------
                if (message.rfind("REGISTER|", 0) == 0) {

                    std::string username =
                        message.substr(9);

                    bool already_used = false;

                    for (int j = 0; j < 2; j++) {

                        if (j != i &&
                            clients[j].fd != -1 &&
                            clients[j].username == username) {

                            already_used = true;
                        }
                    }

                    if (username.empty() || already_used) {

                        send_message(
                            clients[i].fd,
                            "ERROR|Username unavailable\n");

                    } else {

                        clients[i].username = username;

                        std::cout
                            << "Registered: "
                            << username
                            << std::endl;

                        send_message(
                            clients[i].fd,
                            "WELCOME|" + username + "\n");
                    }
                }

                // -------------------------
                // Who is online?
                // -------------------------
                else if (message == "WHO") {

                    std::string response = "USERS|";

                    for (int j = 0; j < 2; j++) {

                        if (clients[j].fd != -1 &&
                            !clients[j].username.empty()) {

                            response += clients[j].username;
                            response += " ";
                        }
                    }

                    response += "\n";

                    send_message(
                        clients[i].fd,
                        response);
                }

                // -------------------------
                // Quit
                // -------------------------
                else if (message == "QUIT") {

                    std::cout
                        << clients[i].username
                        << " disconnected."
                        << std::endl;

                    close(clients[i].fd);
                    clients[i] = Client();
                }

                // -------------------------
                // Chat message
                // CHAT|target|message
                // -------------------------
                else if (message.rfind("CHAT|", 0) == 0) {

                    size_t first_sep =
                        message.find('|');

                    size_t second_sep =
                        message.find('|',
                                     first_sep + 1);

                    if (second_sep == std::string::npos) {
                        continue;
                    }

                    std::string target =
                        message.substr(
                            first_sep + 1,
                            second_sep - first_sep - 1);

                    std::string text =
                        message.substr(second_sep + 1);

                    bool delivered = false;

                    for (int j = 0; j < 2; j++) {

                        if (clients[j].fd != -1 &&
                            clients[j].username == target) {

                            std::string outgoing =
                                "FROM|" +
                                clients[i].username +
                                "|" +
                                text +
                                "\n";

                            // Log plaintext message
                            std::cout
                                << clients[i].username
                                << " -> "
                                << target
                                << ": "
                                << text
                                << std::endl;

                            send_message(
                                clients[j].fd,
                                outgoing);

                            delivered = true;
                            break;
                        }
                    }

                    if (!delivered) {

                        send_message(
                            clients[i].fd,
                            "ERROR|User not online\n");
                    }
                }
            }
        }
    }

    close(server_fd);

    return 0;
}
