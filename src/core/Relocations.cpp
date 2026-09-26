#include "core/Relocations.h"

#include <cstring>

namespace hookscan {

namespace {

constexpr std::uint16_t kAbsolute = 0;
constexpr std::uint16_t kHigh = 1;
constexpr std::uint16_t kLow = 2;
constexpr std::uint16_t kHighLow = 3;
constexpr std::uint16_t kHighAdj = 4;
constexpr std::uint16_t kDir64 = 10;

template <typename T>
bool fits(std::span<std::uint8_t> image, std::uint64_t offset) {
    return offset <= image.size() && image.size() - offset >= sizeof(T);
}

template <typename T>
T load(std::span<std::uint8_t> image, std::uint64_t offset) {
    T value;
    std::memcpy(&value, image.data() + offset, sizeof(T));
    return value;
}

template <typename T>
void store(std::span<std::uint8_t> image, std::uint64_t offset, T value) {
    std::memcpy(image.data() + offset, &value, sizeof(T));
}

} // namespace

RelocationStats applyRelocations(std::span<std::uint8_t> image, std::uint32_t tableRva, std::uint32_t tableSize, std::int64_t delta) {
    RelocationStats stats;
    if (tableSize == 0) {
        return stats;
    }
    if (tableRva > image.size() || image.size() - tableRva < tableSize) {
        stats.malformed = true;
        return stats;
    }

    const auto udelta = static_cast<std::uint64_t>(delta);
    std::uint64_t cursor = tableRva;
    const std::uint64_t end = static_cast<std::uint64_t>(tableRva) + tableSize;

    while (end - cursor >= 8) {
        const auto pageRva = load<std::uint32_t>(image, cursor);
        const auto blockSize = load<std::uint32_t>(image, cursor + 4);
        if (blockSize == 0 && pageRva == 0) {
            break; // some linkers pad the directory with a zero block
        }
        if (blockSize < 8 || blockSize > end - cursor || (blockSize & 1) != 0) {
            stats.malformed = true;
            break;
        }

        const std::uint64_t count = (blockSize - 8) / 2;
        for (std::uint64_t i = 0; i < count; ++i) {
            const auto entry = load<std::uint16_t>(image, cursor + 8 + i * 2);
            const auto type = static_cast<std::uint16_t>(entry >> 12);
            const std::uint64_t target = static_cast<std::uint64_t>(pageRva) + (entry & 0x0FFF);

            switch (type) {
            case kAbsolute:
                ++stats.skipped;
                break;
            case kHighLow:
                if (!fits<std::uint32_t>(image, target)) {
                    ++stats.outOfRange;
                    break;
                }
                store<std::uint32_t>(image, target, static_cast<std::uint32_t>(load<std::uint32_t>(image, target) + udelta));
                ++stats.applied;
                break;
            case kDir64:
                if (!fits<std::uint64_t>(image, target)) {
                    ++stats.outOfRange;
                    break;
                }
                store<std::uint64_t>(image, target, load<std::uint64_t>(image, target) + udelta);
                ++stats.applied;
                break;
            case kHigh:
                if (!fits<std::uint16_t>(image, target)) {
                    ++stats.outOfRange;
                    break;
                }
                store<std::uint16_t>(image, target,
                                     static_cast<std::uint16_t>(load<std::uint16_t>(image, target) + static_cast<std::uint16_t>(udelta >> 16)));
                ++stats.applied;
                break;
            case kLow:
                if (!fits<std::uint16_t>(image, target)) {
                    ++stats.outOfRange;
                    break;
                }
                store<std::uint16_t>(image, target, static_cast<std::uint16_t>(load<std::uint16_t>(image, target) + static_cast<std::uint16_t>(udelta)));
                ++stats.applied;
                break;
            case kHighAdj: {
                // The next entry is not a relocation: it is the low 16 bits of
                // the full 32-bit value, needed to round the high half.
                if (i + 1 >= count) {
                    stats.malformed = true;
                    break;
                }
                const auto low = load<std::int16_t>(image, cursor + 8 + (i + 1) * 2);
                ++i;
                if (!fits<std::uint16_t>(image, target)) {
                    ++stats.outOfRange;
                    break;
                }
                std::uint32_t full = (static_cast<std::uint32_t>(load<std::uint16_t>(image, target)) << 16) + static_cast<std::uint32_t>(low);
                full += static_cast<std::uint32_t>(udelta);
                full += 0x8000;
                store<std::uint16_t>(image, target, static_cast<std::uint16_t>(full >> 16));
                ++stats.applied;
                break;
            }
            default:
                ++stats.unsupported;
                break;
            }
        }
        cursor += blockSize;
    }
    return stats;
}

} // namespace hookscan
