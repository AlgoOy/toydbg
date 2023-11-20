#include <sys/wait.h>
#include <sys/ptrace.h>

#include "linenoise.h"

#include "__common.hpp"
#include "toydbg.hpp"

using namespace toydbg;

void debugger::run() {
    int wait_status = 0, options = 0;
    waitpid(m_pid, &wait_status, options);

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
    else {
        std::cerr << "Unknown command\n";
    }
}

void debugger::continue_execution() {
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);

    int wait_status = 0, options = 0;
    waitpid(m_pid, &wait_status, options);
}