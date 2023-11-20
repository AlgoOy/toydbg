#ifndef __TOYDEG___COMMON_HPP__
#define __TOYDEG___COMMON_HPP__

#include <vector>
#include <string>
#include <sys/cdefs.h>

__BEGIN_DECLS

extern std::vector<std::string> split(const std::string &str, char delimiter);
extern bool is_prefix(const std::string &str, const std::string &prefix);

__END_DECLS

#endif