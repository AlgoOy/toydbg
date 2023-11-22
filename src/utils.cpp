#include <sstream>

#include "__common.hpp"

using namespace toydbg;

std::vector<std::string> toydbg::split(const std::string &str, char delimiter) {
    std::vector<std::string> ret;
    std::stringstream strstream(str);
    std::string token;

    while (std::getline(strstream, token, delimiter)) {
        ret.push_back(token);
    }

    return ret;
}

bool toydbg::is_prefix(const std::string &str, const std::string &prefix) {
    if (str.size() > prefix.size()) {
        return false;
    }

    return std::equal(str.begin(), str.end(), prefix.begin());
}

bool toydbg::is_suffix(const std::string &str, const std::string &of) {
    if (str.size() > of.size()) {
        return false;
    }
    auto diff = of.size() - str.size();
    return std::equal(str.begin(), str.end(), of.begin() + diff);
}

std::string toydbg::to_string(symbol_type st) {
    switch (st) {
    case symbol_type::notype: return "notype";
    case symbol_type::object: return "object";
    case symbol_type::func: return "func";
    case symbol_type::section: return "section";
    case symbol_type::file: return "file";
    default: return "notype";
    }
}

symbol_type toydbg::to_symbol_type(elf::stt sym) {
    switch (sym) {
    case elf::stt::notype: return symbol_type::notype;
    case elf::stt::object: return symbol_type::object;
    case elf::stt::func: return symbol_type::func;
    case elf::stt::section: return symbol_type::section;
    case elf::stt::file: return symbol_type::file;
    default : return symbol_type::notype;
    }
}