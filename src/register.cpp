#include <algorithm>
#include <sys/ptrace.h>
#include <sys/user.h>

#include "register.hpp"

using namespace toydbg;

uint64_t toydbg::get_register_value(pid_t pid, reg r) {
    user_regs_struct regs;
    ptrace(PT_GETREGS, pid, nullptr, &regs);

    auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                           [r](reg_descriptor rd) { return rd.r == r; });
    return *(reinterpret_cast<uint64_t *>(&regs) + (it - begin(g_register_descriptors)));
}

void toydbg::set_register_value(pid_t pid, reg r, uint64_t value) {
    user_regs_struct regs;
    ptrace(PT_GETREGS, pid, nullptr, &regs);

    auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                           [r](reg_descriptor rd) { return rd.r == r; });
    *(reinterpret_cast<uint64_t *>(&regs) + (it - begin(g_register_descriptors))) = value;

    ptrace(PT_SETREGS, pid, nullptr, &regs);
}

uint64_t toydbg::get_register_value_from_dwarf_register(pid_t pid, unsigned int regnum) {
    auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                           [regnum](reg_descriptor rd) { return rd.dwarf_r == regnum; });
    if (it == end(g_register_descriptors)) {
        throw std::out_of_range{"Unknown dwarf register"};
    }

    return get_register_value(pid, it->r);
}

std::string toydbg::get_register_name(reg r) {
    auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                           [r](reg_descriptor rd) { return rd.r == r; });
    return it->name;
}

reg toydbg::get_register_from_name(const std::string &name) {
    auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                           [name](reg_descriptor rd) { return rd.name == name; });
    return it->r;
}