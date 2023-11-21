#ifndef __TOYDBG_REGISTER_HPP__
#define __TOYDBG_REGISTER_HPP__

#include <iostream>
#include <array>
#include <sys/types.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

namespace toydbg {
    enum class reg {
        rax, rbx, rcx, rdx,
        rdi, rsi, rbp, rsp,
        r8,  r9,  r10, r11,
        r12, r13, r14, r15,
        rip, rflags,    cs,
        orig_rax, fs_base,
        gs_base,
        fs, gs, ss, ds, es
    };

    static constexpr std::size_t n_registers = static_cast<int>(reg::es) + 1;

    struct reg_descriptor {
        reg r;
        int8_t dwarf_r;
        std::string name;
    };

    static const std::array<reg_descriptor, n_registers> g_register_descriptors {{
        { reg::r15, 15, "r15" }, 
        { reg::r14, 14, "r14" },
        { reg::r13, 13, "r13" },
        { reg::r12, 12, "r12" },
        { reg::rbp, 6, "rbp" },
        { reg::rbx, 3, "rbx" },
        { reg::r11, 11, "r11" },
        { reg::r10, 10, "r10" },
        { reg::r9, 9, "r9" },
        { reg::r8, 8, "r8" },
        { reg::rax, 0, "rax" },
        { reg::rcx, 2, "rcx" },
        { reg::rdx, 1, "rdx" },
        { reg::rsi, 4, "rsi" },
        { reg::rdi, 5, "rdi" },
        { reg::orig_rax, -1, "orig_rax" },
        { reg::rip, -1, "rip" },
        { reg::cs, 51, "cs" },
        { reg::rflags, 49, "eflags" },
        { reg::rsp, 7, "rsp" },
        { reg::ss, 52, "ss" },
        { reg::fs_base, 58, "fs_base" },
        { reg::gs_base, 59, "gs_base" },
        { reg::ds, 53, "ds" },
        { reg::es, 50, "es" },
        { reg::fs, 54, "fs" },
        { reg::gs, 55, "gs" },
    }};

    uint64_t get_register_value(pid_t pid, reg r);
    void set_register_value(pid_t pid, reg r, uint64_t value);
    uint64_t get_register_value_from_dwarf_register(pid_t pid, unsigned int regnum);
    std::string get_register_name(reg r);
    reg get_register_from_name(const std::string &name);
}

__END_DECLS

#endif