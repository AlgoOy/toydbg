#include <sys/ptrace.h>

#include "breakpoint.hpp"

using namespace toydbg;

void breakpoint::enable() {
    auto data = ptrace(PT_READ_D, m_pid, m_addr, nullptr);
    m_saved_data = static_cast<uint8_t>(data & 0xff);
    uint64_t int3 = 0xcc;
    uint64_t data_with_int3 = ((data & ~0xff) | int3);
    ptrace(PT_WRITE_D, m_pid, m_addr, data_with_int3);

    m_enabled = true;
}

void breakpoint::disable() {
    auto data = ptrace(PT_READ_D, m_pid, m_addr, nullptr);
    auto restored_data = ((data & ~0xff) | m_saved_data);
    ptrace(PT_WRITE_D, m_pid, m_addr, restored_data);

    m_enabled = false;
}