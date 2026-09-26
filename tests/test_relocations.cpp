#include "Bytes.h"

#include "core/Relocations.h"

#include <catch2/catch_test_macros.hpp>

using namespace hookscan;
using namespace test;

namespace {

// A 0x3000-byte image whose relocation table starts at 0x2000.
constexpr std::uint32_t kTable = 0x2000;

std::vector<std::uint8_t> image() {
    return std::vector<std::uint8_t>(0x3000, 0);
}

// Writes one block at `at` and returns the offset after it.
std::size_t block(std::vector<std::uint8_t>& b, std::size_t at, std::uint32_t page, const std::vector<std::uint16_t>& entries) {
    const auto size = static_cast<std::uint32_t>(8 + entries.size() * 2);
    put32(b, at, page);
    put32(b, at + 4, size);
    for (std::size_t i = 0; i < entries.size(); ++i) {
        put16(b, at + 8 + i * 2, entries[i]);
    }
    return at + size;
}

std::uint16_t entry(std::uint16_t type, std::uint16_t offset) {
    return static_cast<std::uint16_t>((type << 12) | offset);
}

} // namespace

TEST_CASE("DIR64 fixups add the delta to 64-bit fields", "[relocations]") {
    auto b = image();
    put64(b, 0x1010, 0x140001234ull);
    put64(b, 0x1FF8, 0x140005678ull); // the last 8 bytes of the page
    const std::size_t end = block(b, kTable, 0x1000, {entry(10, 0x010), entry(10, 0xFF8)});

    const auto stats = applyRelocations(b, kTable, static_cast<std::uint32_t>(end - kTable), 0x7FF600000000ll - 0x140000000ll);
    CHECK(stats.applied == 2);
    CHECK_FALSE(stats.malformed);
    CHECK(get64(b, 0x1010) == 0x7FF600001234ull);
    CHECK(get64(b, 0x1FF8) == 0x7FF600005678ull);
}

TEST_CASE("HIGHLOW fixups wrap in 32 bits and a negative delta works", "[relocations]") {
    auto b = image();
    put32(b, 0x1004, 0x00401000);
    put32(b, 0x1008, 0xFFFFFFF0);
    const std::size_t end = block(b, kTable, 0x1000, {entry(3, 0x004), entry(3, 0x008)});

    const auto stats = applyRelocations(b, kTable, static_cast<std::uint32_t>(end - kTable), -0x100000);
    CHECK(stats.applied == 2);
    CHECK(get32(b, 0x1004) == 0x00301000);
    CHECK(get32(b, 0x1008) == 0xFFEFFFF0);
}

TEST_CASE("ABSOLUTE entries are padding and change nothing", "[relocations]") {
    auto b = image();
    put32(b, 0x1000, 0x11111111);
    const std::size_t end = block(b, kTable, 0x1000, {entry(3, 0x004), entry(0, 0x000)});
    put32(b, 0x1004, 0x10000000);

    const auto stats = applyRelocations(b, kTable, static_cast<std::uint32_t>(end - kTable), 0x10);
    CHECK(stats.applied == 1);
    CHECK(stats.skipped == 1);
    CHECK(get32(b, 0x1000) == 0x11111111); // offset 0 of the ABSOLUTE entry is untouched
    CHECK(get32(b, 0x1004) == 0x10000010);
}

TEST_CASE("HIGH, LOW and HIGHADJ fixups adjust 16-bit halves", "[relocations]") {
    auto b = image();
    put16(b, 0x1000, 0x1234); // HIGH: the high half of an address
    put16(b, 0x1002, 0xFFF0); // LOW: the low half
    put16(b, 0x1004, 0x0040); // HIGHADJ: high half of 0x00407FF0, low half in the next entry
    const std::size_t end = block(b, kTable, 0x1000, {entry(1, 0x000), entry(2, 0x002), entry(4, 0x004), 0x7FF0});

    const auto stats = applyRelocations(b, kTable, static_cast<std::uint32_t>(end - kTable), 0x00018020);
    CHECK(stats.applied == 3);
    CHECK_FALSE(stats.malformed);
    CHECK(get16(b, 0x1000) == 0x1235);
    CHECK(get16(b, 0x1002) == 0x8010);
    // 0x00407FF0 + 0x00018020 = 0x00420010; rounded high half = 0x0042.
    CHECK(get16(b, 0x1004) == 0x0042);
}

TEST_CASE("several blocks are walked in order", "[relocations]") {
    auto b = image();
    put32(b, 0x0100, 1);
    put32(b, 0x1100, 2);
    std::size_t end = block(b, kTable, 0x0000, {entry(3, 0x100), entry(0, 0)});
    end = block(b, end, 0x1000, {entry(3, 0x100), entry(0, 0)});

    const auto stats = applyRelocations(b, kTable, static_cast<std::uint32_t>(end - kTable), 0x1000);
    CHECK(stats.applied == 2);
    CHECK(get32(b, 0x0100) == 0x1001);
    CHECK(get32(b, 0x1100) == 0x1002);
}

TEST_CASE("a zero delta walks the table and changes nothing", "[relocations]") {
    auto b = image();
    put64(b, 0x1010, 0x140001234ull);
    const std::size_t end = block(b, kTable, 0x1000, {entry(10, 0x010)});
    auto withTable = b;

    const auto stats = applyRelocations(withTable, kTable, static_cast<std::uint32_t>(end - kTable), 0);
    CHECK(stats.applied == 1);
    CHECK(withTable == b);
}

TEST_CASE("a fixup that would write past the image is counted, not written", "[relocations]") {
    std::vector<std::uint8_t> b(0x2010, 0);
    // The table sits at the very end; the fixup targets the last 4 bytes, which DIR64 cannot fit.
    const std::size_t end = block(b, 0x2000, 0x2000, {entry(10, 0x00C), entry(3, 0x00C)});
    REQUIRE(end == 0x200C);

    const auto stats = applyRelocations(b, 0x2000, 0xC, 1);
    CHECK(stats.outOfRange == 1);
    CHECK(stats.applied == 1); // the HIGHLOW fits exactly
    CHECK_FALSE(stats.malformed);
}

TEST_CASE("a malformed block stops the walk and says so", "[relocations]") {
    SECTION("block size smaller than its header") {
        auto b = image();
        put32(b, kTable, 0x1000);
        put32(b, kTable + 4, 4);
        const auto stats = applyRelocations(b, kTable, 0x100, 1);
        CHECK(stats.malformed);
        CHECK(stats.applied == 0);
    }
    SECTION("block size past the end of the table") {
        auto b = image();
        put32(b, 0x1000, 0x100);
        block(b, kTable, 0x1000, {entry(3, 0)});
        put32(b, kTable + 4, 0x400);
        const auto stats = applyRelocations(b, kTable, 0x10, 1);
        CHECK(stats.malformed);
        CHECK(get32(b, 0x1000) == 0x100);
    }
    SECTION("the table itself lies outside the image") {
        auto b = image();
        const auto stats = applyRelocations(b, 0x2F00, 0x200, 1);
        CHECK(stats.malformed);
    }
    SECTION("HIGHADJ as the last entry has no low half") {
        auto b = image();
        const std::size_t end = block(b, kTable, 0x1000, {entry(4, 0)});
        const auto stats = applyRelocations(b, kTable, static_cast<std::uint32_t>(end - kTable), 1);
        CHECK(stats.malformed);
    }
}

TEST_CASE("a zero block ends the table early without an error", "[relocations]") {
    auto b = image();
    put32(b, 0x1000, 5);
    std::size_t end = block(b, kTable, 0x1000, {entry(3, 0), entry(0, 0)});
    end += 8; // a zero block, then padding the directory size still counts
    const auto stats = applyRelocations(b, kTable, static_cast<std::uint32_t>(end - kTable + 16), 1);
    CHECK_FALSE(stats.malformed);
    CHECK(stats.applied == 1);
    CHECK(get32(b, 0x1000) == 6);
}

TEST_CASE("types that do not occur on x86 or x64 are counted as unsupported", "[relocations]") {
    auto b = image();
    const std::size_t end = block(b, kTable, 0x1000, {entry(5, 0), entry(7, 4)});
    const auto stats = applyRelocations(b, kTable, static_cast<std::uint32_t>(end - kTable), 1);
    CHECK(stats.unsupported == 2);
    CHECK(stats.applied == 0);
}
