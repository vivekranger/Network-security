#include <string>

using namespace std;

void trim(string &str) {
  string whitespace = " \t\n\r\f\v";

  // Trim from start (left)
  size_t s = str.find_first_not_of(whitespace);
  if (s != string::npos) {
    str.erase(0, s);
  } else {
    // string is empty, just whitespace
    str.clear();
    return;
  }

  // Trim from end (right)
  size_t e = str.find_last_not_of(whitespace);
  if (e != std::string::npos) {
    str.erase(e + 1);
  }
}