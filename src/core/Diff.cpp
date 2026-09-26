#include "core/Diff.h"

#include <algorithm>
#include <cstring>

namespace hookscan {

std::vector<ByteRange> normalizeRanges(std::vector<ByteRange> ranges) {
    std::erase_if(ranges, [](const ByteRange& r) { return r.end <= r.begin; });
    std::sort(ranges.begin(), ranges.end(), [](const ByteRange& a, const ByteRange& b) { return a.begin < b.begin; });
    std::vector<ByteRange> out;
    for (const ByteRange& r : ranges) {
        if (!out.empty() && r.begin <= out.back().end) {
            out.back().end = std::max(out.back().end, r.end);
        } else {
            out.push_back(r);
        }
    }
    return out;
}

std::vector<ByteRange> diffRegions(std::span<const std::uint8_t> expected, std::span<const std::uint8_t> actual, std::vector<ByteRange> ignore,
                                   std::uint32_t mergeGap) {
    const std::uint32_t length = static_cast<std::uint32_t>(std::min(expected.size(), actual.size()));
    ignore = normalizeRanges(std::move(ignore));

    std::vector<ByteRange> regions;
    bool open = false; // whether regions.back() may still grow
    std::size_t nextIgnore = 0;
    std::uint32_t pos = 0;

    while (pos < length) {
        while (nextIgnore < ignore.size() && ignore[nextIgnore].end <= pos) {
            ++nextIgnore;
        }
        std::uint32_t stop = length;
        if (nextIgnore < ignore.size()) {
            if (ignore[nextIgnore].begin <= pos) {
                pos = ignore[nextIgnore].end;
                open = false;
                continue;
            }
            stop = std::min(stop, ignore[nextIgnore].begin);
        }

        while (pos < stop) {
            // Skip equal chunks quickly; nearly all of every module is equal.
            const std::uint32_t chunkEnd = pos + std::min<std::uint32_t>(stop - pos, 4096);
            if (std::memcmp(expected.data() + pos, actual.data() + pos, chunkEnd - pos) == 0) {
                pos = chunkEnd;
                continue;
            }
            for (; pos < chunkEnd; ++pos) {
                if (expected[pos] == actual[pos]) {
                    continue;
                }
                if (open && pos - regions.back().end <= mergeGap) {
                    regions.back().end = pos + 1;
                } else {
                    regions.push_back({pos, pos + 1});
                    open = true;
                }
            }
        }
    }
    return regions;
}

} // namespace hookscan
