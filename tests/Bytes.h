#pragma once

// Little-endian helpers for building synthetic buffers in tests.

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace test {

inline void put16(std::vector<std::uint8_t>& b, std::size_t at, std::uint16_t v) {
    std::memcpy(b.data() + at, &v, 2);
}
inline void put32(std::vector<std::uint8_t>& b, std::size_t at, std::uint32_t v) {
    std::memcpy(b.data() + at, &v, 4);
}
inline void put64(std::vector<std::uint8_t>& b, std::size_t at, std::uint64_t v) {
    std::memcpy(b.data() + at, &v, 8);
}
inline std::uint16_t get16(const std::vector<std::uint8_t>& b, std::size_t at) {
    std::uint16_t v;
    std::memcpy(&v, b.data() + at, 2);
    return v;
}
inline std::uint32_t get32(const std::vector<std::uint8_t>& b, std::size_t at) {
    std::uint32_t v;
    std::memcpy(&v, b.data() + at, 4);
    return v;
}
inline std::uint64_t get64(const std::vector<std::uint8_t>& b, std::size_t at) {
    std::uint64_t v;
    std::memcpy(&v, b.data() + at, 8);
    return v;
}
inline void putString(std::vector<std::uint8_t>& b, std::size_t at, const std::string& s) {
    std::memcpy(b.data() + at, s.c_str(), s.size() + 1);
}

} // namespace test
