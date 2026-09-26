#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace hookscan {

struct RelocationStats {
    std::size_t applied = 0;     // fixups written
    std::size_t skipped = 0;     // padding (ABSOLUTE) entries
    std::size_t outOfRange = 0;  // fixups that would write past the image
    std::size_t unsupported = 0; // types that do not occur on x86 or x64 (ARM, MIPS, RISC-V)
    bool malformed = false;      // a block header was truncated or impossible; the walk stopped there
};

// Applies the base relocation table at [tableRva, tableRva + tableSize) of an
// image-layout buffer, adding `delta` (actual base minus preferred base) to
// every fixup. The table is read from the same buffer. Handles ABSOLUTE,
// HIGH, LOW, HIGHLOW, HIGHADJ and DIR64. A delta of zero still walks the
// table, so the stats describe it.
RelocationStats applyRelocations(std::span<std::uint8_t> image, std::uint32_t tableRva, std::uint32_t tableSize, std::int64_t delta);

} // namespace hookscan
