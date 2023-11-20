#include <sstream>

#include "__common.hpp"

std::vector<std::string> split(const std::string &str, char delimiter) {
    std::vector<std::string> ret;
    std::stringstream strstream(str);
    std::string token;

    while (std::getline(strstream, token, delimiter)) {
        ret.push_back(token);
    }

    return ret;
}

bool is_prefix(const std::string &str, const std::string &prefix) {
    if (str.size() > prefix.size()) {
        return false;
    }

    return std::equal(str.begin(), str.end(), prefix.begin());
}