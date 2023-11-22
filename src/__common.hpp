#ifndef __TOYDEG___COMMON_HPP__
#define __TOYDEG___COMMON_HPP__

#include <vector>
#include <string>
#include <sys/cdefs.h>

#include "debugger.hpp"

__BEGIN_DECLS

namespace toydbg {
    std::vector<std::string> split(const std::string &str, char delimiter);
    bool is_prefix(const std::string &str, const std::string &prefix);
    bool is_suffix(const std::string &str, const std::string &of);

    std::string to_string(symbol_type st);
    symbol_type to_symbol_type(elf::stt sym);
}

__END_DECLS

#endif