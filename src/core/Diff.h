#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace hookscan {

// A half-open byte range [begin, end), as offsets into the buffers compared.
struct ByteRange {
    std::uint32_t begin = 0;
    std::uint32_t end = 0;

    friend bool operator==(const ByteRange&, const ByteRange&) = default;
};

// Compares `expected` with `actual` (compared up to the shorter length) and
// groups differing bytes into regions. Two differences with at most
// `mergeGap` equal bytes between them belong to the same region: a 14-byte
// absolute jump often keeps a byte or two of the original by chance, and it
// is one patch, not three.
//
// Bytes inside `ignore` are not compared, and a region never spans an ignored
// range: an IAT slot the loader filled in sits next to code, and a patch on
// either side of it is its own finding. `ignore` need not be sorted and may
// overlap.
[[nodiscard]] std::vector<ByteRange> diffRegions(std::span<const std::uint8_t> expected, std::span<const std::uint8_t> actual,
                                                 std::vector<ByteRange> ignore, std::uint32_t mergeGap);

// Merges overlapping or touching ranges and sorts them.
[[nodiscard]] std::vector<ByteRange> normalizeRanges(std::vector<ByteRange> ranges);

} // namespace hookscan
