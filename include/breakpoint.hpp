#ifndef __TOYDBG_BREAKPOINT_HPP__
#define __TOYDBG_BREAKPOINT_HPP__

#include <iostream>
#include <sys/cdefs.h>

__BEGIN_DECLS

namespace toydbg {
    class breakpoint {
        public:
            breakpoint() = default;
            breakpoint(pid_t pid, std::intptr_t addr) 
                : m_pid{pid}, m_addr{addr}, m_enabled{false}, m_saved_data{} {}

            void enable();
            void disable();

            const bool is_enabled() { return m_enabled; }
            const std::intptr_t get_address() { return m_addr; }

        private:
            pid_t m_pid;
            std::intptr_t m_addr;
            bool m_enabled;
            uint8_t m_saved_data;
    };
}

__END_DECLS

#endif