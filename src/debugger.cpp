#include <sys/wait.h>
#include <sys/ptrace.h>
#include <iomanip>
#include <fstream>

#include "linenoise.h"

#include "__common.hpp"
#include "debugger.hpp"
#include "register.hpp"

using namespace toydbg;

void debugger::run() {
    wait_for_signal();
    initialise_load_address();

    char *line = nullptr;
    while((line = linenoise(TOYDBG_PROMPT)) != nullptr) {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}

void debugger::handle_command(const std::string &line) {
    auto args = split(line, ' ');
    const std::string command = args[0];

    if (is_prefix(command, "continue")) {
        continue_execution();
    }
    else if (is_prefix(command, "break")) {
        if (args[1][0] == '0' && args[1][1] == 'x') {
            std::string addr {args[1], 2};
            set_breakpoint_at_address(std::stol(addr, 0, 16));
        }
        else if (args[1].find(':') != std::string::npos) {
            auto file_and_line = split(args[1], ':');
            set_breakpoint_at_source_line(file_and_line[0], std::stoi(file_and_line[1]));
        }
        else {
            set_breakpoint_at_function(args[1]);
        }
    }
    else if (is_prefix(command, "step")) {
        step_in();
    }
    else if (is_prefix(command, "next")) {
        step_over();
    }
    else if (is_prefix(command, "finish")) {
        step_out();
    }
    else if (is_prefix(command, "register")) {
        if (is_prefix(args[1], "dump")) {
            dump_registers();
        }
        else if (is_prefix(args[1], "read")) {
            std::cout << get_register_value(m_pid, get_register_from_name(args[2])) << std::endl;
        }
        else if (is_prefix(args[1], "write")) {
            std::string val {args[3], 2};
            set_register_value(m_pid, get_register_from_name(args[2]), std::stol(val, 0, 16));
        }
    }
    else if (is_prefix(command, "memory")) {
        std::string addr {args[2], 2};
        if (is_prefix(args[1], "read")) {
            std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << std::endl;
        }
        else if (is_prefix(args[1], "write")) {
            std::string val {args[3], 2};
            write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
        }
    }
    else if (is_prefix(command, "symbol")) {
        auto syms = lookup_symbol(args[1]);
        for (auto &&s : syms) {
            std::cout << s.name << " 0x" << std::hex << offset_dwarf_address(s.addr) << std::endl;
        }
    }
    else if (is_prefix(command, "stepi")) {
        single_step_instruction_with_breakpoint_check();
        auto line_entry = get_line_entry_from_pc(get_offset_pc());
        print_source(line_entry->file->path, line_entry->line);
    }
    else {
        std::cerr << "Unknown command\n";
    }
}

void debugger::continue_execution() {
    step_over_breakpoint();

    ptrace(PT_CONTINUE, m_pid, nullptr, nullptr);

    wait_for_signal();
}

void debugger::set_breakpoint_at_address(std::intptr_t addr) {
    std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;
    breakpoint bp{m_pid, addr};
    bp.enable();
    m_breakpoints[addr] = bp;
}

void debugger::dump_registers() {
    for (const auto &rd : g_register_descriptors) {
        std::cout << std::setfill(' ') << std::setw(8) << rd.name 
            << " 0x" << std::setfill('0') << std::setw(16) << std::hex 
            << get_register_value(m_pid, rd.r) << std::endl;
    }
}

uint64_t debugger::read_memory(uint64_t address) {
    return ptrace(PT_READ_D, m_pid, reinterpret_cast<void *>(address), nullptr);
}

void debugger::write_memory(uint64_t address, uint64_t value) {
    ptrace(PT_WRITE_D, m_pid, reinterpret_cast<void *>(address), value);
}

uint64_t debugger::get_pc() {
    return get_register_value(m_pid, reg::rip);
}

void debugger::set_pc(uint64_t pc) {
    set_register_value(m_pid, reg::rip, pc);
}

void debugger::step_over_breakpoint() {
    if (m_breakpoints.count(get_pc())) {
        auto &bp = m_breakpoints[get_pc()];
        if (bp.is_enabled()) {
            bp.disable();
            ptrace(PT_STEP, m_pid, nullptr, nullptr);
            wait_for_signal();
            bp.enable();
        }
    }
}

void debugger::wait_for_signal() {
    int wait_status = 0, options = 0;
    waitpid(m_pid, &wait_status, options);

    auto siginfo = get_signal_info();
    switch (siginfo.si_signo) {
    case SIGTRAP:
        handle_sigtrap(siginfo);
        break;
    case SIGSEGV:
        std::cout << "Yay, segfault. Reason: " << siginfo.si_code << std::endl;
        break;
    default:
        std::cout << "Got signal " << strsignal(siginfo.si_signo) << std::endl;
    }
}

dwarf::die debugger::get_function_from_pc(uint64_t pc) {
    for (auto &cu : m_dwarf.compilation_units()) {
        if (die_pc_range(cu.root()).contains(pc)) {
            for (const auto &die : cu.root()) {
                if (die.tag == dwarf::DW_TAG::subprogram) {
                    if (die_pc_range(die).contains(pc)) {
                        return die;
                    }
                }
            }
        }
    }

    throw std::out_of_range{"Cannot find function"};
}

dwarf::line_table::iterator debugger::get_line_entry_from_pc(uint64_t pc) {
    for (auto &cu : m_dwarf.compilation_units()) {
        if (die_pc_range(cu.root()).contains(pc)) {
            auto &lt = cu.get_line_table();

            auto it = lt.find_address(pc);
            if (it == lt.end()) {
                throw std::out_of_range{"Cannot find line entry"};
            }
            else {
                return it;
            }
        }
    }

    throw std::out_of_range{"Cannot find line entry"};
}

void debugger::initialise_load_address() {
    if (m_elf.get_hdr().type == elf::et::dyn) {
        std::ifstream map{"/proc/" + std::to_string(m_pid) + "/maps"};

        std::string addr;
        std::getline(map, addr, '-');

        m_load_address = std::stol(addr, 0, 16);
    }
}

uint64_t debugger::offset_load_address(uint64_t addr) {
    return addr - m_load_address;
}

void debugger::print_source(const std::string &file_name, unsigned int line, 
                                unsigned int n_lines_context) {
    std::ifstream file{file_name};

    auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
    auto end_line = line + n_lines_context + (line < n_lines_context ? 
                        n_lines_context - line : 0) + 1;
    
    char c{};
    auto current_line = 1u;
    while (current_line != start_line && file.get(c)) {
        if (c == '\n') {
            ++current_line;
        }
    }

    std::cout << (current_line == line ? "> " : " ");

    while (current_line <= end_line && file.get(c)) {
        std::cout << c;

        if (c == '\n') {
            ++current_line;
            std::cout << (current_line == line ? "> " : " ");
        }
    }

    std::cout << std::endl;
}

siginfo_t debugger::get_signal_info() {
    siginfo_t info;
    ptrace(PT_GETSIGINFO, m_pid, nullptr, &info);
    return info;
}

void debugger::handle_sigtrap(siginfo_t info) {
    switch (info.si_code) {
    case SI_KERNEL:
    case TRAP_BRKPT: {
        set_pc(get_pc() - 1);
        std::cout << "Hit breakpoint at address 0x" << std::hex << get_pc() << std::endl;
        auto line_entry = get_line_entry_from_pc(get_offset_pc());
        print_source(line_entry->file->path, line_entry->line);
        return;
    }
    case TRAP_TRACE:
        return;
    default:
        std::cout << "Unknown SIGTRAP code " << info.si_code << std::endl;
        return;
    }
}

void debugger::single_step_instruction() {
    ptrace(PT_STEP, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void debugger::single_step_instruction_with_breakpoint_check() {
    if (m_breakpoints.count(get_pc())) {
        step_over_breakpoint();
    }
    else {
        single_step_instruction();
    }
}

void debugger::step_in() {
    auto line = get_line_entry_from_pc(get_offset_pc())->line;

    while (get_line_entry_from_pc(get_offset_pc())->line == line) {
        single_step_instruction_with_breakpoint_check();
    }

    auto line_entry = get_line_entry_from_pc(get_offset_pc());
    print_source(line_entry->file->path, line_entry->line);
}

void debugger::step_over() {
    auto func = get_function_from_pc(get_offset_pc());
    auto func_entry = at_low_pc(func);
    auto func_end = at_high_pc(func);

    auto line_entry = get_line_entry_from_pc(func_entry);
    auto start_line = get_line_entry_from_pc(get_offset_pc());

    std::vector<std::intptr_t> to_delete{};

    while (line_entry->address < func_end) {
        auto load_address = offset_dwarf_address(line_entry->address);
        if (line_entry->address != start_line->address && !m_breakpoints.count(load_address)) {
            set_breakpoint_at_address(load_address);
            to_delete.push_back(load_address);
        }
        ++line_entry;
    }

    auto frame_pointer = get_register_value(m_pid, reg::rbp);
    auto return_address = read_memory(frame_pointer + 8);
    if (!m_breakpoints.count(return_address)) {
        set_breakpoint_at_address(return_address);
        to_delete.push_back(return_address);
    }

    continue_execution();
    for (auto addr : to_delete) {
        remove_breakpoint(addr);
    }
}

void debugger::step_out() {
    auto frame_pointer = get_register_value(m_pid, reg::rbp);
    auto return_address = read_memory(frame_pointer + 8);

    bool should_remove_breakpoint = false;
    if (!m_breakpoints.count(return_address)) {
        set_breakpoint_at_address(return_address);
        should_remove_breakpoint = true;
    }

    continue_execution();

    if (should_remove_breakpoint) {
        remove_breakpoint(return_address);
    }
}

void debugger::remove_breakpoint(std::intptr_t addr) {
    if (m_breakpoints.at(addr).is_enabled()) {
        m_breakpoints.at(addr).disable();
    }
    m_breakpoints.erase(addr);
}

uint64_t debugger::get_offset_pc() {
    return offset_load_address(get_pc());
}

uint64_t debugger::offset_dwarf_address(uint64_t addr) {
    return addr + m_load_address;
}

void debugger::set_breakpoint_at_function(const std::string &name) {
    for (const auto &cu : m_dwarf.compilation_units()) {
        for (const auto &die : cu.root()) {
            if (die.has(dwarf::DW_AT::name) && at_name(die) == name) {
                auto low_pc = at_low_pc(die);
                auto entry = get_line_entry_from_pc(low_pc);
                ++entry; //skip prologue
                set_breakpoint_at_address(offset_dwarf_address(entry->address));
            }
        }
    }
}

void debugger::set_breakpoint_at_source_line(const std::string &file, unsigned int line) {
    for (const auto &cu : m_dwarf.compilation_units()) {
        if (is_suffix(file, at_name(cu.root()))) {
            const auto &lt = cu.get_line_table();
            for (const auto &entry : lt) {
                if (entry.is_stmt && entry.line == line) {
                    set_breakpoint_at_address(offset_dwarf_address(entry.address));
                    return;
                }
            }
        }
    }
}

std::vector<symbol> debugger::lookup_symbol(const std::string &name) {
    std::vector<symbol> syms;

    for (auto &sec : m_elf.sections()) {
        if (sec.get_hdr().type != elf::sht::symtab && sec.get_hdr().type != elf::sht::dynsym) {
            continue;
        }

        for (auto sym : sec.as_symtab()) {
            if (sym.get_name() == name) {
                auto &d = sym.get_data();
                syms.push_back(symbol{to_symbol_type(d.type()), name, d.value});
            }
        }
    }

    return syms;
}