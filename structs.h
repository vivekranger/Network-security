#pragma once
#include <string>

struct Client {
    int id;
    int fd;
    vuc key;
    string username;
    string input_buffer;
    bool ready;
};
