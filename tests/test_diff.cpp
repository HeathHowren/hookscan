#include "core/Diff.h"

#include <catch2/catch_test_macros.hpp>

using namespace hookscan;

namespace {

std::vector<std::uint8_t> zeros(std::size_t n) {
    return std::vector<std::uint8_t>(n, 0);
}

} // namespace

TEST_CASE("identical buffers have no regions", "[diff]") {
    const auto a = zeros(10000);
    CHECK(diffRegions(a, a, {}, 8).empty());
    CHECK(diffRegions({}, {}, {}, 8).empty());
}

TEST_CASE("one changed byte is one region of one byte", "[diff]") {
    const auto a = zeros(100);
    auto b = a;
    b[42] = 0xCC;
    const auto regions = diffRegions(a, b, {}, 8);
    REQUIRE(regions.size() == 1);
    CHECK(regions[0] == ByteRange{42, 43});
}

TEST_CASE("changes separated by up to the gap merge; one more byte splits them", "[diff]") {
    const auto a = zeros(100);

    auto merged = a;
    merged[10] = 1;
    merged[19] = 1; // 8 equal bytes between (11..18)
    auto regions = diffRegions(a, merged, {}, 8);
    REQUIRE(regions.size() == 1);
    CHECK(regions[0] == ByteRange{10, 20});

    auto split = a;
    split[10] = 1;
    split[20] = 1; // 9 equal bytes between
    regions = diffRegions(a, split, {}, 8);
    REQUIRE(regions.size() == 2);
    CHECK(regions[0] == ByteRange{10, 11});
    CHECK(regions[1] == ByteRange{20, 21});

    regions = diffRegions(a, merged, {}, 0);
    CHECK(regions.size() == 2);
}

TEST_CASE("a 14-byte absolute jump that keeps two original bytes is one region", "[diff]") {
    std::vector<std::uint8_t> original = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x90};
    auto patched = original;
    // FF 25 00 00 00 00 <imm64>, where one byte of the imm64 happens to equal the original.
    const std::uint8_t jump[] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x57, 0x7F, 0x00, 0x00};
    std::copy(std::begin(jump), std::end(jump), patched.begin());
    const auto regions = diffRegions(original, patched, {}, 8);
    REQUIRE(regions.size() == 1);
    CHECK(regions[0].begin == 0);
    CHECK(regions[0].end == 14);
}

TEST_CASE("a change in the last byte is found", "[diff]") {
    const auto a = zeros(64);
    auto b = a;
    b[63] = 7;
    const auto regions = diffRegions(a, b, {}, 8);
    REQUIRE(regions.size() == 1);
    CHECK(regions[0] == ByteRange{63, 64});
}

TEST_CASE("changes inside ignored ranges are not reported", "[diff]") {
    const auto a = zeros(100);
    auto b = a;
    b[5] = 1;
    b[50] = 1;
    b[51] = 1;
    const auto regions = diffRegions(a, b, {{48, 56}}, 8);
    REQUIRE(regions.size() == 1);
    CHECK(regions[0] == ByteRange{5, 6});
}

TEST_CASE("a region never spans an ignored range, even within the gap", "[diff]") {
    const auto a = zeros(100);
    auto b = a;
    b[10] = 1;
    b[15] = 1;
    const auto regions = diffRegions(a, b, {{12, 13}}, 8);
    REQUIRE(regions.size() == 2);
    CHECK(regions[0] == ByteRange{10, 11});
    CHECK(regions[1] == ByteRange{15, 16});
}

TEST_CASE("ignored ranges may be unsorted, overlapping, empty or past the end", "[diff]") {
    const auto a = zeros(100);
    auto b = a;
    for (std::size_t i = 0; i < 100; ++i) {
        b[i] = 1;
    }
    const auto regions = diffRegions(a, b, {{60, 200}, {0, 20}, {10, 30}, {40, 40}, {25, 35}}, 0);
    REQUIRE(regions.size() == 1);
    CHECK(regions[0] == ByteRange{35, 60});
}

TEST_CASE("buffers of different lengths are compared up to the shorter", "[diff]") {
    const auto a = zeros(10);
    auto b = zeros(20);
    b[15] = 1;
    CHECK(diffRegions(a, b, {}, 8).empty());
    b[9] = 1;
    const auto regions = diffRegions(a, b, {}, 8);
    REQUIRE(regions.size() == 1);
    CHECK(regions[0] == ByteRange{9, 10});
}

TEST_CASE("regions across the fast-compare chunk boundary are found and merged", "[diff]") {
    const auto a = zeros(3 * 4096 + 17);
    auto b = a;
    b[4095] = 1;
    b[4097] = 1;   // merges with 4095 across the 4096 boundary
    b[8192] = 1;   // first byte of the third chunk
    b[3 * 4096 + 16] = 1; // last byte, in the short tail chunk
    const auto regions = diffRegions(a, b, {}, 8);
    REQUIRE(regions.size() == 3);
    CHECK(regions[0] == ByteRange{4095, 4098});
    CHECK(regions[1] == ByteRange{8192, 8193});
    CHECK(regions[2] == ByteRange{3 * 4096 + 16, 3 * 4096 + 17});
}

TEST_CASE("normalizeRanges sorts, merges touching ranges and drops empty ones", "[diff]") {
    const auto out = normalizeRanges({{20, 30}, {5, 10}, {10, 12}, {40, 40}, {25, 35}, {50, 49}});
    REQUIRE(out.size() == 2);
    CHECK(out[0] == ByteRange{5, 12});
    CHECK(out[1] == ByteRange{20, 35});
}
