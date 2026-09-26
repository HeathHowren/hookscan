#pragma once

#include <cstddef>
#include <cstdint>

namespace hookscan {

// Read access to an address space: a live process, or a test buffer.
class MemoryReader {
public:
    virtual ~MemoryReader() = default;

    // Copies `size` bytes at `address` into `out`. Returns false, and leaves
    // `out` unspecified, if any byte of the range could not be read.
    virtual bool read(std::uint64_t address, void* out, std::size_t size) const = 0;
};

} // namespace hookscan
