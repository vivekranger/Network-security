#pragma once
#include <string>

struct Client {
    int fd = -1; // Initially till the time any client is connected, initializing fd as -1
    std::string username;
    std::string input_buffer;
};
