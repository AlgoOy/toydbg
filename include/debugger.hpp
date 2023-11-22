#ifndef __TOYDBG_DEBUGGER_HPP__
#define __TOYDBG_DEBUGGER_HPP__

#include <iostream>
#include <unordered_map>
#include <sys/cdefs.h>
#include <fcntl.h>
#include <signal.h>

#include "dwarf/dwarf++.hh"
#include "elf/elf++.hh"

#include "breakpoint.hpp"

__BEGIN_DECLS

#define TOYDBG_PROMPT "(toydbg) "

namespace toydbg {
    enum class symbol_type {
        notype,            // No type (e.g., absolute symbol)
        object,            // Data object
        func,              // Function entry point
        section,           // Symbol is associated with a section
        file,              // Source file associated with the
    };

    struct symbol {
        symbol_type type;
        std::string name;
        std::uintptr_t addr;
    };

    class debugger {
        public:
            debugger (std::string prog_name, pid_t pid)
                : m_prog_name{prog_name}, m_pid{pid} {
                auto fd = open(m_prog_name.c_str(), O_RDONLY);

                m_elf = elf::elf{elf::create_mmap_loader(fd)};
                m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};
            }

            void run();

            void set_breakpoint_at_address(std::intptr_t addr);
            void set_breakpoint_at_function(const std::string &name);
            void set_breakpoint_at_source_line(const std::string &file, unsigned int line);
            void remove_breakpoint(std::intptr_t addr);

            void dump_registers();

            void print_source(const std::string &file_name, unsigned int line, unsigned int n_lines_context = 2);

            std::vector<symbol> lookup_symbol(const std::string &name);

            void single_step_instruction();
            void single_step_instruction_with_breakpoint_check();
            void step_in();
            void step_over();
            void step_out();

        private:
            void handle_command(const std::string &line);

            void continue_execution();
            void step_over_breakpoint();

            void wait_for_signal();
            siginfo_t get_signal_info();
            void handle_sigtrap(siginfo_t info);

            uint64_t read_memory(uint64_t address);
            void write_memory(uint64_t address, uint64_t value);

            uint64_t get_pc();
            uint64_t get_offset_pc();
            void set_pc(uint64_t pc);

            void initialise_load_address();
            uint64_t offset_load_address(uint64_t addr);
            uint64_t offset_dwarf_address(uint64_t addr);

            dwarf::die get_function_from_pc(uint64_t pc);
            dwarf::line_table::iterator get_line_entry_from_pc(uint64_t pc);

            const std::string m_prog_name;
            const pid_t m_pid;
            uint64_t m_load_address = 0;

            std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;
            
            dwarf::dwarf m_dwarf;
            elf::elf m_elf;
    };
}

__END_DECLS

#endif