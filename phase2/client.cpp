#include <iostream>
#include <cstring>
#include <string>
#include <vector>

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "crypto.h"


void send_message(
    int fd,
    const std::string& message)
{
    send(
        fd,
        message.c_str(),
        message.size(),
        0
    );
}


//
// Read one complete newline-delimited message.
//
bool receive_line(
    int fd,
    std::string& buffer,
    std::string& line)
{
    while (true) {

        size_t pos =
            buffer.find('\n');

        if (pos != std::string::npos) {

            line =
                buffer.substr(
                    0,
                    pos
                );

            buffer.erase(
                0,
                pos + 1
            );

            return true;
        }

        char temp[4096];

        int bytes =
            recv(
                fd,
                temp,
                sizeof(temp),
                0
            );

        if (bytes <= 0) {
            return false;
        }

        buffer.append(
            temp,
            bytes
        );
    }
}


//
// Perform DH exchange with server.
//
bool perform_dh_handshake(
    int client_fd,
    std::vector<unsigned char>& aes_key)
{
    //
    // Generate client's DH private/public values.
    //
    DHKeyPair client_dh =
        generate_dh_keypair();


    //
    // Send client's public value.
    //
    std::string client_public =
        bn_to_string(
            client_dh.public_key
        );


    send_message(
        client_fd,
        "DH|" +
        client_public +
        "\n"
    );


    //
    // Receive server's public value.
    //
    std::string buffer;
    std::string line;


    if (!receive_line(
            client_fd,
            buffer,
            line)) {

        return false;
    }


    if (line.rfind(
            "DH|",
            0) != 0) {

        return false;
    }


    std::string server_public_text =
        line.substr(3);


    BIGNUM* server_public =
        string_to_bn(
            server_public_text
        );


    if (!server_public) {
        return false;
    }


    //
    // Calculate shared secret.
    //
    BIGNUM* shared_secret =
        compute_dh_shared_secret(
            client_dh.private_key,
            server_public
        );


    //
    // Derive AES-256 key using SHA-256.
    //
    aes_key =
        derive_aes_key(
            shared_secret
        );


    //
    // Print only fingerprint.
    //
    std::cout
        << "DH shared-secret fingerprint: "
        << fingerprint(shared_secret)
        << std::endl;


    //
    // Clean up.
    //
    BN_free(server_public);

    BN_free(client_dh.private_key);

    BN_free(client_dh.public_key);

    BN_free(shared_secret);


    return true;
}


int main()
{
    //
    // Create TCP socket.
    //
    int client_fd =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );


    if (client_fd == -1) {
        return 1;
    }


    sockaddr_in server_addr{};

    server_addr.sin_family =
        AF_INET;

    server_addr.sin_port =
        htons(5000);


    //
    // Server IP address.
    //
    inet_pton(
        AF_INET,
        "192.168.64.3",
        &server_addr.sin_addr
    );


    //
    // Connect to server.
    //
    if (connect(
            client_fd,
            (struct sockaddr*)&server_addr,
            sizeof(server_addr)
        ) == -1) {

        return 1;
    }


    std::cout
        << "Connected to server!"
        << std::endl;


    //
    // Perform DH before registration.
    //
    std::vector<unsigned char> aes_key;


    if (!perform_dh_handshake(
            client_fd,
            aes_key)) {

        std::cerr
            << "DH handshake failed."
            << std::endl;

        close(client_fd);

        return 1;
    }


    std::cout
        << "Secure channel established."
        << std::endl;


    //
    // Get username.
    //
    std::string username;


    std::cout
        << "Enter username: ";


    std::getline(
        std::cin,
        username
    );


    //
    // Registration is now encrypted.
    //
    std::string registration =
        "REGISTER|" +
        username;


    std::string encrypted_registration =
        aes_gcm_encrypt(
            registration,
            aes_key
        );


    send_message(
        client_fd,
        "ENC|" +
        bytes_to_hex(
            encrypted_registration
        ) +
        "\n"
    );


    //
    // Buffer for messages received
    // from the server.
    //
    std::string server_buffer;


    std::string selected_user;


    fd_set read_fds;


    while (true) {

        FD_ZERO(&read_fds);


        //
        // Watch keyboard.
        //
        FD_SET(
            STDIN_FILENO,
            &read_fds
        );


        //
        // Watch server.
        //
        FD_SET(
            client_fd,
            &read_fds
        );


        int max_fd =
            client_fd;


        //
        // Wait for keyboard or server.
        //
        int activity =
            select(
                max_fd + 1,
                &read_fds,
                nullptr,
                nullptr,
                nullptr
            );


        if (activity == -1) {
            return 1;
        }


        //
        // Check keyboard.
        //
        if (FD_ISSET(
                STDIN_FILENO,
                &read_fds)) {


            std::string input;


            std::getline(
                std::cin,
                input
            );


            //
            // -------------------------
            // /quit
            // -------------------------
            if (input == "/quit") {


                std::string message =
                    "QUIT";


                std::string encrypted =
                    aes_gcm_encrypt(
                        message,
                        aes_key
                    );


                send_message(
                    client_fd,
                    "ENC|" +
                    bytes_to_hex(
                        encrypted
                    ) +
                    "\n"
                );


                break;
            }


            //
            // -------------------------
            // /who
            // -------------------------
            else if (
                input == "/who") {


                std::string message =
                    "WHO";


                std::string encrypted =
                    aes_gcm_encrypt(
                        message,
                        aes_key
                    );


                send_message(
                    client_fd,
                    "ENC|" +
                    bytes_to_hex(
                        encrypted
                    ) +
                    "\n"
                );
            }


            //
            // -------------------------
            // /chat username
            // -------------------------
            else if (
                input.rfind(
                    "/chat ",
                    0
                ) == 0) {


                selected_user =
                    input.substr(6);


                std::cout
                    << "Now chatting with "
                    << selected_user
                    << std::endl;
            }


            //
            // -------------------------
            // @username message
            // -------------------------
            else if (
                !input.empty() &&
                input[0] == '@') {


                size_t space =
                    input.find(' ');


                if (
                    space ==
                    std::string::npos) {


                    std::cout
                        << "Usage: @username message"
                        << std::endl;


                    continue;
                }


                selected_user =
                    input.substr(
                        1,
                        space - 1
                    );


                std::string text =
                    input.substr(
                        space + 1
                    );


                std::string message =
                    "CHAT|" +
                    selected_user +
                    "|" +
                    text;


                std::string encrypted =
                    aes_gcm_encrypt(
                        message,
                        aes_key
                    );


                send_message(
                    client_fd,
                    "ENC|" +
                    bytes_to_hex(
                        encrypted
                    ) +
                    "\n"
                );
            }


            //
            // -------------------------
            // Normal chat message
            // -------------------------
            else {


                if (
                    selected_user.empty()) {


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
                    input;


                std::string encrypted =
                    aes_gcm_encrypt(
                        message,
                        aes_key
                    );


                send_message(
                    client_fd,
                    "ENC|" +
                    bytes_to_hex(
                        encrypted
                    ) +
                    "\n"
                );
            }
        }


        //
        // Check server.
        //
        if (FD_ISSET(
                client_fd,
                &read_fds)) {


            std::string message;


            if (!receive_line(
                    client_fd,
                    server_buffer,
                    message)) {


                std::cout
                    << "Server disconnected."
                    << std::endl;


                break;
            }


            //
            // Everything from server should
            // now be encrypted.
            //
            if (
                message.rfind(
                    "ENC|",
                    0
                ) != 0) {

                continue;
            }


            std::string encoded =
                message.substr(4);


            std::string encrypted =
                hex_to_bytes(
                    encoded
                );


            std::string decrypted;


            //
            // AES-GCM verifies the message here.
            //
            if (!aes_gcm_decrypt(
                    encrypted,
                    aes_key,
                    decrypted)) {


                std::cerr
                    << "AES-GCM authentication failed!"
                    << std::endl;


                continue;
            }


            //
            // -------------------------
            // Welcome
            // -------------------------
            if (
                decrypted.rfind(
                    "WELCOME|",
                    0
                ) == 0) {


                std::cout
                    << "Username registered."
                    << std::endl;
            }


            //
            // -------------------------
            // Online users
            // -------------------------
            else if (
                decrypted.rfind(
                    "USERS|",
                    0
                ) == 0) {


                std::string users =
                    decrypted.substr(6);


                std::cout
                    << "Online users: "
                    << users
                    << std::endl;
            }


            //
            // -------------------------
            // Incoming chat
            // -------------------------
            else if (
                decrypted.rfind(
                    "FROM|",
                    0
                ) == 0) {


                size_t first_sep =
                    decrypted.find('|');


                size_t second_sep =
                    decrypted.find(
                        '|',
                        first_sep + 1
                    );


                std::string sender =
                    decrypted.substr(
                        first_sep + 1,
                        second_sep -
                        first_sep - 1
                    );


                std::string text =
                    decrypted.substr(
                        second_sep + 1
                    );


                std::cout
                    << sender
                    << ": "
                    << text
                    << std::endl;
            }


            //
            // -------------------------
            // Error
            // -------------------------
            else if (
                decrypted.rfind(
                    "ERROR|",
                    0
                ) == 0) {


                std::cout
                    << decrypted.substr(6)
                    << std::endl;
            }
        }
    }


    close(client_fd);

    return 0;
}
