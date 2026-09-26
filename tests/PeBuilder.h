#pragma once

// Builds small synthetic PE images for the parser tests. Everything is
// written by RVA into an image-layout buffer; file() lays the same content out
// as a file with 0x200 file alignment.

#include "Bytes.h"

#include <string>
#include <vector>

namespace test {

class PeBuilder {
public:
    struct Section {
        std::string name;
        std::uint32_t va;
        std::uint32_t size;
        std::uint32_t characteristics;
    };

    static constexpr std::uint32_t kCode = 0x60000020;  // code | execute | read
    static constexpr std::uint32_t kData = 0x40000040;  // initialized data | read
    static constexpr std::uint32_t kWrite = 0xC0000040; // initialized data | read | write

    explicit PeBuilder(bool is64, std::uint32_t sizeOfImage = 0x5000, std::uint64_t imageBase = 0)
        : is64_(is64), image_(sizeOfImage, 0), imageBase_(imageBase ? imageBase : (is64 ? 0x140000000ull : 0x400000ull)) {}

    PeBuilder& section(const std::string& name, std::uint32_t va, std::uint32_t size, std::uint32_t characteristics) {
        sections_.push_back({name, va, size, characteristics});
        return *this;
    }
    PeBuilder& directory(unsigned index, std::uint32_t rva, std::uint32_t size) {
        directories_[index][0] = rva;
        directories_[index][1] = size;
        return *this;
    }

    std::vector<std::uint8_t>& raw() { return image_; }
    [[nodiscard]] const std::vector<std::uint8_t>& raw() const { return image_; }
    [[nodiscard]] bool is64() const { return is64_; }
    [[nodiscard]] std::uint64_t imageBase() const { return imageBase_; }
    [[nodiscard]] std::uint32_t pointerSize() const { return is64_ ? 8 : 4; }
    void pointer(std::size_t rva, std::uint64_t value) {
        if (is64_) {
            put64(image_, rva, value);
        } else {
            put32(image_, rva, static_cast<std::uint32_t>(value));
        }
    }

    [[nodiscard]] std::vector<std::uint8_t> image() const {
        auto out = image_;
        writeHeaders(out, false);
        return out;
    }

    [[nodiscard]] std::vector<std::uint8_t> file() const {
        std::vector<std::uint8_t> out(0x400, 0);
        for (const Section& s : sections_) {
            const std::size_t rawSize = (s.size + 0x1FF) & ~std::size_t{0x1FF};
            const std::size_t offset = out.size();
            out.resize(offset + rawSize, 0);
            for (std::size_t i = 0; i < s.size && s.va + i < image_.size(); ++i) {
                out[offset + i] = image_[s.va + i];
            }
        }
        writeHeaders(out, true);
        return out;
    }

private:
    void writeHeaders(std::vector<std::uint8_t>& out, bool fileLayout) const {
        for (std::size_t i = 0; i < 0x400 && i < out.size(); ++i) {
            out[i] = 0;
        }
        put16(out, 0, 0x5A4D);
        put32(out, 0x3C, 0x80);
        put32(out, 0x80, 0x00004550);
        const std::size_t fh = 0x84;
        put16(out, fh, is64_ ? 0x8664 : 0x014C);
        put16(out, fh + 2, static_cast<std::uint16_t>(sections_.size()));
        put32(out, fh + 4, 0x12345678);
        const std::uint16_t optionalSize = is64_ ? 0xF0 : 0xE0;
        put16(out, fh + 16, optionalSize);
        put16(out, fh + 18, 0x0022);
        const std::size_t oh = fh + 20;
        put16(out, oh, is64_ ? 0x20B : 0x10B);
        put32(out, oh + 16, 0x1000);
        if (is64_) {
            put64(out, oh + 24, imageBase_);
        } else {
            put32(out, oh + 28, static_cast<std::uint32_t>(imageBase_));
        }
        put32(out, oh + 32, 0x1000);
        put32(out, oh + 36, 0x200);
        put32(out, oh + 56, static_cast<std::uint32_t>(image_.size()));
        put32(out, oh + 60, 0x400);
        const std::size_t dirCount = oh + (is64_ ? 108 : 92);
        put32(out, dirCount, 16);
        for (unsigned i = 0; i < 16; ++i) {
            put32(out, dirCount + 4 + i * 8, directories_[i][0]);
            put32(out, dirCount + 8 + i * 8, directories_[i][1]);
        }
        std::size_t table = oh + optionalSize;
        std::uint32_t rawOffset = 0x400;
        for (const Section& s : sections_) {
            for (std::size_t i = 0; i < 8 && i < s.name.size(); ++i) {
                out[table + i] = static_cast<std::uint8_t>(s.name[i]);
            }
            const std::uint32_t rawSize = (s.size + 0x1FF) & ~0x1FFu;
            put32(out, table + 8, s.size);
            put32(out, table + 12, s.va);
            put32(out, table + 16, rawSize);
            put32(out, table + 20, fileLayout ? rawOffset : s.va);
            put32(out, table + 36, s.characteristics);
            rawOffset += rawSize;
            table += 40;
        }
    }

    bool is64_;
    std::vector<std::uint8_t> image_;
    std::uint64_t imageBase_;
    std::vector<Section> sections_;
    std::uint32_t directories_[16][2] = {};
};

} // namespace test
