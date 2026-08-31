#include <iostream>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int main() {

    // Create TCP socket
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (client_fd == -1) {
        return 1;
    }

    sockaddr_in server_addr{};

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(5000);

    // Server IP address
    inet_pton(AF_INET,
              "192.168.64.3",
              &server_addr.sin_addr);

    // Connect to server
    if (connect(client_fd,
                (struct sockaddr*)&server_addr,
                sizeof(server_addr)) == -1) {
        return 1;
    }

    std::cout << "Connected to server!" << std::endl;

    // Get username
    std::string username;

    std::cout << "Enter username: ";
    std::getline(std::cin, username);

    std::string registration =
        "REGISTER|" + username + "\n";

    send(client_fd,
         registration.c_str(),
         registration.size(),
         0);

    std::string selected_user;

    fd_set read_fds;

    while (true) {

        FD_ZERO(&read_fds);

        // Watch keyboard
        FD_SET(STDIN_FILENO, &read_fds);

        // Watch server
        FD_SET(client_fd, &read_fds);

        int max_fd = client_fd;

        // Wait for keyboard or server
        int activity = select(max_fd + 1,
                              &read_fds,
                              nullptr,
                              nullptr,
                              nullptr);

        if (activity == -1) {
            return 1;
        }

        // Check keyboard
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {

            std::string input;

            std::getline(std::cin, input);

            // -------------------------
            // /quit
            // -------------------------
            if (input == "/quit") {

                std::string message = "QUIT\n";

                send(client_fd,
                     message.c_str(),
                     message.size(),
                     0);

                break;
            }

            // -------------------------
            // /who
            // -------------------------
            else if (input == "/who") {

                std::string message = "WHO\n";

                send(client_fd,
                     message.c_str(),
                     message.size(),
                     0);
            }

            // -------------------------
            // /chat username
            // -------------------------
            else if (input.rfind("/chat ", 0) == 0) {

                selected_user =
                    input.substr(6);

                std::cout
                    << "Now chatting with "
                    << selected_user
                    << std::endl;
            }

            // -------------------------
            // @username message
            // -------------------------
            else if (!input.empty() &&
                     input[0] == '@') {

                size_t space =
                    input.find(' ');

                if (space == std::string::npos) {

                    std::cout
                        << "Usage: @username message"
                        << std::endl;

                    continue;
                }

                selected_user =
                    input.substr(1, space - 1);

                std::string text =
                    input.substr(space + 1);

                std::string message =
                    "CHAT|" +
                    selected_user +
                    "|" +
                    text +
                    "\n";

                send(client_fd,
                     message.c_str(),
                     message.size(),
                     0);
            }

            // -------------------------
            // Normal chat message
            // -------------------------
            else {

                if (selected_user.empty()) {

                    std::cout
                        << "Select a user first using "
                        << "@username or /chat username"
                        << std::endl;

                    continue;
                }

                std::string message =
                    "CHAT|" +
                    selected_user +
                    "|" +
                    input +
                    "\n";

                send(client_fd,
                     message.c_str(),
                     message.size(),
                     0);
            }
        }

        // Check server
        if (FD_ISSET(client_fd, &read_fds)) {

            char buffer[1024];

            int bytes_recd =
                recv(client_fd,
                     buffer,
                     sizeof(buffer) - 1,
                     0);

            if (bytes_recd <= 0) {

                std::cout
                    << "Server disconnected."
                    << std::endl;

                break;
            }

            buffer[bytes_recd] = '\0';

            std::string message(buffer);

            // -------------------------
            // Welcome
            // -------------------------
            if (message.rfind("WELCOME|", 0) == 0) {

                std::cout
                    << "Username registered."
                    << std::endl;
            }

            // -------------------------
            // Online users
            // -------------------------
            else if (message.rfind("USERS|", 0) == 0) {

                std::string users =
                    message.substr(6);

                std::cout
                    << "Online users: "
                    << users;
            }

            // -------------------------
            // Incoming chat
            // -------------------------
            else if (message.rfind("FROM|", 0) == 0) {

                size_t first_sep =
                    message.find('|');

                size_t second_sep =
                    message.find('|',
                                 first_sep + 1);

                std::string sender =
                    message.substr(
                        first_sep + 1,
                        second_sep - first_sep - 1);

                std::string text =
                    message.substr(second_sep + 1);

                std::cout
                    << sender
                    << ": "
                    << text;
            }

            // -------------------------
            // Error
            // -------------------------
            else if (message.rfind("ERROR|", 0) == 0) {

                std::cout
                    << message.substr(6);
            }
        }
    }

    close(client_fd);

    return 0;
}
