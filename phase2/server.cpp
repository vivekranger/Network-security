#include <iostream>
#include <cstring>
#include <string>
#include <vector>

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <unistd.h>

#include "crypto.h"


struct Client {

    int fd = -1;

    std::string username;

    std::string input_buffer;

    //
    // AES key belonging to this
    // particular client-server connection.
    //
    std::vector<unsigned char> aes_key;

    bool crypto_ready = false;
};


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
                buffer.substr(0, pos);

            buffer.erase(
                0,
                pos + 1
            );

            return true;
        }

        char temp[1024];

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
// Perform DH handshake with one client.
//
bool perform_dh_handshake(
    Client& client)
{
    std::string line;

    //
    // Client sends:
    //
    // DH|client_public_key
    //
    if (!receive_line(
            client.fd,
            client.input_buffer,
            line)) {

        return false;
    }

    if (line.rfind("DH|", 0) != 0) {

        send_message(
            client.fd,
            "ERROR|DH handshake failed\n"
        );

        return false;
    }

    std::string client_public_text =
        line.substr(3);

    BIGNUM* client_public =
        string_to_bn(
            client_public_text
        );

    if (!client_public) {
        return false;
    }


    //
    // Server generates its own DH key pair.
    //
    DHKeyPair server_dh =
        generate_dh_keypair();


    //
    // Server sends its public value.
    //
    std::string server_public =
        bn_to_string(
            server_dh.public_key
        );

    send_message(
        client.fd,
        "DH|" +
        server_public +
        "\n"
    );


    //
    // Calculate the shared secret.
    //
    BIGNUM* shared_secret =
        compute_dh_shared_secret(
            server_dh.private_key,
            client_public
        );


    //
    // Convert shared secret into AES-256 key.
    //
    client.aes_key =
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
    // We no longer need the DH values.
    //
    BN_free(client_public);

    BN_free(server_dh.private_key);

    BN_free(server_dh.public_key);

    BN_free(shared_secret);


    client.crypto_ready = true;

    return true;
}


int main()
{
    //
    // Create TCP socket
    //
    int server_fd =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

    if (server_fd == -1) {
        return 1;
    }


    sockaddr_in server_addr{};

    server_addr.sin_family =
        AF_INET;

    server_addr.sin_port =
        htons(5000);

    server_addr.sin_addr.s_addr =
        INADDR_ANY;


    //
    // Bind socket to port 5000
    //
    if (bind(
            server_fd,
            (struct sockaddr*)&server_addr,
            sizeof(server_addr)
        ) == -1) {

        return 1;
    }


    //
    // Start listening
    //
    if (listen(
            server_fd,
            5
        ) == -1) {

        return 1;
    }


    std::cout
        << "Secure server is running..."
        << std::endl;


    Client clients[2];

    fd_set read_fds;


    while (true) {

        FD_ZERO(&read_fds);

        //
        // Watch for new clients.
        //
        FD_SET(
            server_fd,
            &read_fds
        );

        int max_fd =
            server_fd;


        //
        // Watch connected clients.
        //
        for (int i = 0; i < 2; i++) {

            if (clients[i].fd != -1) {

                FD_SET(
                    clients[i].fd,
                    &read_fds
                );

                if (clients[i].fd > max_fd) {

                    max_fd =
                        clients[i].fd;
                }
            }
        }


        //
        // Wait for something to happen.
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
        // Check for a new client.
        //
        if (FD_ISSET(
                server_fd,
                &read_fds)) {

            int new_client =
                accept(
                    server_fd,
                    nullptr,
                    nullptr
                );

            if (new_client != -1) {

                int slot = -1;

                for (int i = 0; i < 2; i++) {

                    if (clients[i].fd == -1) {

                        slot = i;

                        break;
                    }
                }


                if (slot != -1) {

                    clients[slot].fd =
                        new_client;


                    std::cout
                        << "New client connected."
                        << std::endl;


                    //
                    // Perform DH immediately
                    // for this connection.
                    //
                    if (!perform_dh_handshake(
                            clients[slot])) {

                        close(
                            clients[slot].fd
                        );

                        clients[slot] =
                            Client();
                    }
                }
                else {

                    send_message(
                        new_client,
                        "ERROR|Server full\n"
                    );

                    close(new_client);
                }
            }
        }


        //
        // Check both clients.
        //
        for (int i = 0; i < 2; i++) {

            if (clients[i].fd == -1) {
                continue;
            }


            if (!FD_ISSET(
                    clients[i].fd,
                    &read_fds)) {

                continue;
            }


            char buffer[4096];


            int bytes_recd =
                recv(
                    clients[i].fd,
                    buffer,
                    sizeof(buffer),
                    0
                );


            if (bytes_recd <= 0) {

                std::cout
                    << clients[i].username
                    << " disconnected."
                    << std::endl;


                close(
                    clients[i].fd
                );

                clients[i] =
                    Client();

                continue;
            }


            clients[i].input_buffer.append(
                buffer,
                bytes_recd
            );


            //
            // Process complete lines.
            //
            size_t newline_pos;


            while (
                (newline_pos =
                    clients[i].input_buffer.find('\n'))
                != std::string::npos) {


                std::string message =
                    clients[i].input_buffer.substr(
                        0,
                        newline_pos
                    );


                clients[i].input_buffer.erase(
                    0,
                    newline_pos + 1
                );


                //
                // Every normal message after DH
                // must be AES-GCM encrypted.
                //
                if (!clients[i].crypto_ready) {
                    continue;
                }


                //
                // Decode hexadecimal ciphertext.
                //
                if (message.rfind(
                        "ENC|",
                        0) != 0) {

                    send_message(
                        clients[i].fd,
                        "ERROR|Encrypted message required\n"
                    );

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
                // AES-GCM authentication happens here.
                //
                if (!aes_gcm_decrypt(
                        encrypted,
                        clients[i].aes_key,
                        decrypted)) {

                    std::cerr
                        << "AES-GCM authentication failed for client."
                        << std::endl;

                    send_message(
                        clients[i].fd,
                        "ERROR|AES-GCM authentication failed\n"
                    );

                    continue;
                }


                //
                // From this point onwards,
                // 'decrypted' contains the Phase 1
                // protocol message.
                //
                std::string plain_message =
                    decrypted;


                //
                // -------------------------
                // Register username
                // -------------------------
                if (
                    plain_message.rfind(
                        "REGISTER|",
                        0
                    ) == 0) {


                    std::string username =
                        plain_message.substr(9);


                    bool already_used =
                        false;


                    for (int j = 0; j < 2; j++) {

                        if (
                            j != i &&
                            clients[j].fd != -1 &&
                            clients[j].username ==
                                username) {

                            already_used =
                                true;
                        }
                    }


                    if (
                        username.empty() ||
                        already_used) {

                        std::string reply =
                            "ERROR|Username unavailable";


                        std::string encrypted_reply =
                            aes_gcm_encrypt(
                                reply,
                                clients[i].aes_key
                            );


                        send_message(
                            clients[i].fd,
                            "ENC|" +
                            bytes_to_hex(
                                encrypted_reply
                            ) +
                            "\n"
                        );
                    }
                    else {

                        clients[i].username =
                            username;


                        std::cout
                            << "Registered: "
                            << username
                            << std::endl;


                        std::string reply =
                            "WELCOME|" +
                            username;


                        std::string encrypted_reply =
                            aes_gcm_encrypt(
                                reply,
                                clients[i].aes_key
                            );


                        send_message(
                            clients[i].fd,
                            "ENC|" +
                            bytes_to_hex(
                                encrypted_reply
                            ) +
                            "\n"
                        );
                    }
                }


                //
                // -------------------------
                // Who is online?
                // -------------------------
                else if (
                    plain_message == "WHO") {


                    std::string response =
                        "USERS|";


                    for (int j = 0; j < 2; j++) {

                        if (
                            clients[j].fd != -1 &&
                            !clients[j].username.empty()) {

                            response +=
                                clients[j].username;

                            response += " ";
                        }
                    }


                    std::string encrypted_response =
                        aes_gcm_encrypt(
                            response,
                            clients[i].aes_key
                        );


                    send_message(
                        clients[i].fd,
                        "ENC|" +
                        bytes_to_hex(
                            encrypted_response
                        ) +
                        "\n"
                    );
                }


                //
                // -------------------------
                // Quit
                // -------------------------
                else if (
                    plain_message == "QUIT") {


                    std::cout
                        << clients[i].username
                        << " disconnected."
                        << std::endl;


                    close(
                        clients[i].fd
                    );


                    clients[i] =
                        Client();
                }


                //
                // -------------------------
                // Chat message
                //
                // CHAT|target|message
                // -------------------------
                else if (
                    plain_message.rfind(
                        "CHAT|",
                        0
                    ) == 0) {


                    size_t first_sep =
                        plain_message.find('|');


                    size_t second_sep =
                        plain_message.find(
                            '|',
                            first_sep + 1
                        );


                    if (
                        second_sep ==
                        std::string::npos) {

                        continue;
                    }


                    std::string target =
                        plain_message.substr(
                            first_sep + 1,
                            second_sep -
                            first_sep - 1
                        );


                    std::string text =
                        plain_message.substr(
                            second_sep + 1
                        );


                    bool delivered =
                        false;


                    for (int j = 0; j < 2; j++) {

                        if (
                            clients[j].fd != -1 &&
                            clients[j].username ==
                                target) {


                            //
                            // Server logs plaintext.
                            //
                            std::cout
                                << clients[i].username
                                << " -> "
                                << target
                                << ": "
                                << text
                                << std::endl;


                            //
                            // Encrypt using the
                            // destination client's
                            // own AES key.
                            //
                            std::string outgoing =
                                "FROM|" +
                                clients[i].username +
                                "|" +
                                text;


                            std::string encrypted_outgoing =
                                aes_gcm_encrypt(
                                    outgoing,
                                    clients[j].aes_key
                                );


                            send_message(
                                clients[j].fd,
                                "ENC|" +
                                bytes_to_hex(
                                    encrypted_outgoing
                                ) +
                                "\n"
                            );


                            delivered =
                                true;

                            break;
                        }
                    }


                    if (!delivered) {

                        std::string error =
                            "ERROR|User not online";


                        std::string encrypted_error =
                            aes_gcm_encrypt(
                                error,
                                clients[i].aes_key
                            );


                        send_message(
                            clients[i].fd,
                            "ENC|" +
                            bytes_to_hex(
                                encrypted_error
                            ) +
                            "\n"
                        );
                    }
                }
            }
        }
    }


    close(server_fd);

    return 0;
}
