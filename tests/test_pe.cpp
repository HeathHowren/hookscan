#include "PeBuilder.h"

#include "core/PeImage.h"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>

using namespace hookscan;
using namespace test;

namespace {

// A small image with code, exports, imports, an IAT in .data and one
// relocation. Laid out the same way for 32 and 64 bits.
PeBuilder sample(bool is64) {
    PeBuilder pe(is64);
    pe.section(".text", 0x1000, 0x100, PeBuilder::kCode)
        .section(".rdata", 0x2000, 0x800, PeBuilder::kData)
        .section(".data", 0x3000, 0x100, PeBuilder::kWrite)
        .section(".reloc", 0x4000, 0x20, PeBuilder::kData);
    auto& b = pe.raw();
    const std::uint32_t ptr = pe.pointerSize();

    // Code bytes to find at their RVA after layout.
    b[0x1000] = 0x55;
    b[0x10FF] = 0xC3;

    // Exports: three functions from ordinal 5; the second is a forwarder, the third has no name.
    pe.directory(0, 0x2000, 0x100);
    put32(b, 0x2000 + 12, 0x2080);
    put32(b, 0x2000 + 16, 5);
    put32(b, 0x2000 + 20, 3);
    put32(b, 0x2000 + 24, 2);
    put32(b, 0x2000 + 28, 0x2040);
    put32(b, 0x2000 + 32, 0x2050);
    put32(b, 0x2000 + 36, 0x2058);
    put32(b, 0x2040, 0x1000);
    put32(b, 0x2044, 0x2090);
    put32(b, 0x2048, 0x1010);
    put32(b, 0x2050, 0x20C0); // "Beta" first, so the parser has to sort
    put32(b, 0x2054, 0x20B0);
    put16(b, 0x2058, 1);
    put16(b, 0x205A, 0);
    putString(b, 0x2080, "t.dll");
    putString(b, 0x2090, "NTDLL.RtlFoo");
    putString(b, 0x20B0, "Alpha");
    putString(b, 0x20C0, "Beta");

    // Imports: KERNEL32.dll!GetTickCount by name, and ordinal 12.
    pe.directory(1, 0x2200, 40);
    put32(b, 0x2200, 0x2300);
    put32(b, 0x2200 + 12, 0x2280);
    put32(b, 0x2200 + 16, 0x3000);
    putString(b, 0x2280, "KERNEL32.dll");
    const std::uint64_t ordinalFlag = is64 ? 0x8000000000000000ull : 0x80000000ull;
    pe.pointer(0x2300, 0x2340);
    pe.pointer(0x2300 + ptr, ordinalFlag | 12);
    putString(b, 0x2342, "GetTickCount");
    pe.pointer(0x3000, 0x2340);
    pe.pointer(0x3000 + ptr, ordinalFlag | 12);
    pe.directory(12, 0x3000, 3 * ptr);

    // One absolute pointer in .data, and the relocation that covers it.
    pe.pointer(0x3080, pe.imageBase() + 0x1000);
    pe.directory(5, 0x4000, 12);
    put32(b, 0x4000, 0x3000);
    put32(b, 0x4004, 12);
    put16(b, 0x4008, static_cast<std::uint16_t>(((is64 ? 10 : 3) << 12) | 0x080));
    put16(b, 0x400A, 0);
    return pe;
}

std::optional<PeImage> parseFile(const PeBuilder& pe) {
    const auto file = pe.file();
    std::string error;
    auto image = PeImage::fromFile(file, &error);
    INFO(error);
    REQUIRE(image);
    return image;
}

} // namespace

TEST_CASE("a file is laid out with every section at its RVA", "[pe]") {
    for (const bool is64 : {true, false}) {
        const auto pe = sample(is64);
        const auto file = pe.file();
        REQUIRE(file.size() < pe.raw().size()); // the file really is packed tighter than the image
        const auto image = parseFile(pe);
        CHECK(image->is64() == is64);
        CHECK(image->imageBase() == pe.imageBase());
        CHECK(image->sizeOfImage() == 0x5000);
        CHECK(image->bytes().size() == 0x5000);
        CHECK(image->timeDateStamp() == 0x12345678);
        CHECK(image->bytes()[0x1000] == 0x55);
        CHECK(image->bytes()[0x10FF] == 0xC3);
        REQUIRE(image->sections().size() == 4);
        CHECK(image->sections()[0].name == ".text");
        CHECK(image->sections()[0].executable());
        CHECK_FALSE(image->sections()[0].writable());
        CHECK(image->sections()[2].writable());
        CHECK(image->sectionAt(0x2010) == &image->sections()[1]);
        CHECK(image->sectionAt(0x4800) == nullptr);
    }
}

TEST_CASE("exports: names, ordinals and forwarders", "[pe]") {
    const auto image = parseFile(sample(true));
    const ExportTable exports = image->exports();
    REQUIRE(exports.functions.size() == 3);
    CHECK(exports.ordinalBase == 5);
    CHECK(exports.eatRva == 0x2040);
    CHECK(exports.indexOfName("Alpha") == 0u);
    CHECK(exports.indexOfName("Beta") == 1u);
    CHECK_FALSE(exports.indexOfName("Gamma"));
    CHECK(exports.indexOfOrdinal(7) == 2u);
    CHECK_FALSE(exports.indexOfOrdinal(4));
    CHECK_FALSE(exports.indexOfOrdinal(8));
    CHECK(exports.forwarders[0].empty());
    CHECK(exports.forwarders[1] == "NTDLL.RtlFoo");
    CHECK(exports.names[2].empty());
    CHECK(exports.functions[2] == 0x1010);
}

TEST_CASE("imports: by name and by ordinal, with their IAT slots", "[pe]") {
    for (const bool is64 : {true, false}) {
        const auto image = parseFile(sample(is64));
        const auto imports = image->imports();
        REQUIRE(imports.size() == 1);
        CHECK(imports[0].dll == "KERNEL32.dll");
        CHECK_FALSE(imports[0].delayLoad);
        REQUIRE(imports[0].entries.size() == 2);
        CHECK(imports[0].entries[0].name == "GetTickCount");
        CHECK_FALSE(imports[0].entries[0].byOrdinal);
        CHECK(imports[0].entries[0].iatRva == 0x3000);
        CHECK(imports[0].entries[1].byOrdinal);
        CHECK(imports[0].entries[1].ordinal == 12);
        CHECK(imports[0].entries[1].iatRva == 0x3000 + (is64 ? 8u : 4u));
    }
}

TEST_CASE("relocate moves absolute pointers to the load address", "[pe]") {
    for (const bool is64 : {true, false}) {
        auto image = parseFile(sample(is64));
        const std::uint64_t base = is64 ? 0x7FF612340000ull : 0x00A30000ull;
        std::string error;
        CHECK(image->relocate(base, &error) == 1);
        CHECK(error.empty());
        CHECK(image->loadedBase() == base);
        CHECK(image->readPointer(0x3080) == base + 0x1000);
        // RVAs, such as the export table's, are not touched.
        CHECK(image->exports().functions[0] == 0x1000);
    }
}

TEST_CASE("loader-written ranges cover the IAT and the load configuration pointers", "[pe]") {
    auto pe = sample(true);
    auto& b = pe.raw();
    pe.directory(10, 0x2400, 0x140);
    put32(b, 0x2400, 0x140);
    put64(b, 0x2400 + 88, pe.imageBase() + 0x1080);  // SecurityCookie, placed in .text on purpose
    put64(b, 0x2400 + 112, pe.imageBase() + 0x3090); // GuardCFCheckFunctionPointer
    const auto image = parseFile(pe);

    const auto ranges = image->loaderWrittenRanges();
    auto has = [&](std::uint32_t begin, std::uint32_t end) {
        return std::any_of(ranges.begin(), ranges.end(), [&](const RvaRange& r) { return r.begin <= begin && r.end >= end; });
    };
    CHECK(has(0x3000, 0x3018)); // the IAT
    CHECK(has(0x1080, 0x1088)); // the cookie
    CHECK(has(0x3090, 0x3098)); // the CFG check pointer
    CHECK_FALSE(has(0x1000, 0x1010));
    CHECK(std::is_sorted(ranges.begin(), ranges.end(), [](const RvaRange& x, const RvaRange& y) { return x.begin < y.begin; }));
}

TEST_CASE("load configuration fields past the declared size are ignored", "[pe]") {
    auto pe = sample(true);
    auto& b = pe.raw();
    pe.directory(10, 0x2400, 0x140);
    put32(b, 0x2400, 96); // declares only up to SecurityCookie
    put64(b, 0x2400 + 88, pe.imageBase() + 0x1080);
    put64(b, 0x2400 + 112, pe.imageBase() + 0x1090);
    put64(b, 0x2400 + 192, pe.imageBase() + 0x2600); // DynamicValueRelocTable, also past the size
    const auto image = parseFile(pe);
    const auto ranges = image->loaderWrittenRanges();
    CHECK(std::any_of(ranges.begin(), ranges.end(), [](const RvaRange& r) { return r.begin == 0x1080; }));
    CHECK_FALSE(std::any_of(ranges.begin(), ranges.end(), [](const RvaRange& r) { return r.begin == 0x1090; }));
    CHECK_FALSE(image->hasDynamicRelocations());

    put32(b, 0x2400, 0x140);
    CHECK(parseFile(pe)->hasDynamicRelocations());
}

TEST_CASE("x64 runtime functions are read and sorted", "[pe]") {
    auto pe = sample(true);
    auto& b = pe.raw();
    pe.directory(3, 0x2500, 24);
    put32(b, 0x2500, 0x1040);
    put32(b, 0x2504, 0x1080);
    put32(b, 0x250C, 0x1000);
    put32(b, 0x2510, 0x1040);
    const auto functions = parseFile(pe)->runtimeFunctions();
    REQUIRE(functions.size() == 2);
    CHECK(functions[0].begin == 0x1000);
    CHECK(functions[1].begin == 0x1040);
    CHECK(parseFile(sample(false))->runtimeFunctions().empty());
}

TEST_CASE("malformed headers are refused with a reason", "[pe]") {
    const auto good = sample(true).file();
    std::string error;

    SECTION("no MZ") {
        auto bad = good;
        bad[0] = 'X';
        CHECK_FALSE(PeImage::fromFile(bad, &error));
        CHECK(error == "no MZ header");
    }
    SECTION("e_lfanew past the end") {
        auto bad = good;
        put32(bad, 0x3C, 0x7FFFFFF0);
        CHECK_FALSE(PeImage::fromFile(bad, &error));
        CHECK(error == "no PE signature");
    }
    SECTION("truncated inside the optional header") {
        const std::vector<std::uint8_t> bad(good.begin(), good.begin() + 0xA0);
        CHECK_FALSE(PeImage::fromFile(bad, &error));
        CHECK_FALSE(error.empty());
    }
    SECTION("an unknown optional header magic") {
        auto bad = good;
        put16(bad, 0x98, 0x107);
        CHECK_FALSE(PeImage::fromFile(bad, &error));
        CHECK(error == "unknown optional header magic");
    }
    SECTION("an implausible SizeOfImage") {
        auto bad = good;
        put32(bad, 0x98 + 56, 0xF0000000);
        CHECK_FALSE(PeImage::fromFile(bad, &error));
        CHECK(error == "implausible SizeOfImage");
    }
    SECTION("an empty buffer") {
        CHECK_FALSE(PeImage::fromFile({}, &error));
    }
}

TEST_CASE("tables that point outside the image come back empty", "[pe]") {
    auto pe = sample(true);
    auto& b = pe.raw();
    put32(b, 0x2000 + 20, 0x00FFFFFF); // NumberOfFunctions far past the image
    CHECK(parseFile(pe)->exports().empty());

    auto broken = sample(true);
    broken.directory(1, 0x4FF0, 40); // descriptors run off the end
    CHECK(parseFile(broken)->imports().empty());
}

TEST_CASE("sections whose raw data runs past the file are truncated, not read out of bounds", "[pe]") {
    auto file = sample(true).file();
    file.resize(0x480); // keeps the headers and the first 0x80 bytes of .text
    const auto image = PeImage::fromFile(file);
    REQUIRE(image);
    CHECK(image->bytes()[0x1000] == 0x55);
    CHECK(image->bytes()[0x10FF] == 0x00); // beyond the truncated file
    CHECK(image->imports().empty());
}
