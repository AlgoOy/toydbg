#ifndef __TOYDBG_HPP__
#define __TOYDBG_HPP__

#include <iostream>
#include <sys/cdefs.h>

__BEGIN_DECLS

#define TOYDBG_PROMPT "(toydbg) "

namespace toydbg {
    class debugger {
        public:
            debugger (std::string prog_name, pid_t pid)
                : m_prog_name{prog_name}, m_pid{pid} {}

            void run();

        private:
            void handle_command(const std::string &line);
            void continue_execution();

            const std::string m_prog_name;
            const pid_t m_pid;
    };
}

__END_DECLS

#endif