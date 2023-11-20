#include <iostream>
#include <unistd.h>
#include <sys/ptrace.h>

#include "toydbg.hpp"

using namespace toydbg;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: toydbg <binary file>" << std::endl;
        return 1;
    }

    const char *prog = argv[1];

    pid_t pid = fork();

    if (pid == 0) {
        // child process
        ptrace(PT_TRACE_ME, 0, nullptr, nullptr);
        execl(prog, prog, nullptr);
    }
    else if (pid >= 1) {
        // parent process
        std::cout << "Started debugging process " << pid << std::endl;
        debugger dbg(prog, pid);
        dbg.run();
    }
    else {
        std::cerr << "fork() failed" << std::endl;
        return -1;
    }

    return 0;
}