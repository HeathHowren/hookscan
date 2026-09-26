#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace hookscan {

// A half-open range of RVAs, [begin, end).
struct RvaRange {
    std::uint32_t begin = 0;
    std::uint32_t end = 0;
};

struct Section {
    std::string name;
    std::uint32_t virtualAddress = 0;
    // The size the section occupies in memory: VirtualSize, or SizeOfRawData
    // when a linker left VirtualSize zero.
    std::uint32_t virtualSize = 0;
    std::uint32_t rawOffset = 0;
    std::uint32_t rawSize = 0;
    std::uint32_t characteristics = 0;

    [[nodiscard]] bool executable() const;
    [[nodiscard]] bool writable() const;
};

struct ImportEntry {
    std::string name;          // empty when imported by ordinal
    std::uint16_t ordinal = 0; // set when imported by ordinal
    bool byOrdinal = false;
    std::uint32_t iatRva = 0;  // where the loader writes the resolved address
};

struct ImportModule {
    std::string dll;
    bool delayLoad = false;
    std::vector<ImportEntry> entries;
};

// The export table as the file declares it. The EAT holds RVAs, which
// relocation does not touch, so the file's values are what memory should hold.
struct ExportTable {
    std::uint32_t ordinalBase = 0;
    std::uint32_t eatRva = 0;                // AddressOfFunctions
    std::uint32_t directoryRva = 0;          // an RVA inside [directoryRva, +size) is a forwarder string
    std::uint32_t directorySize = 0;
    std::vector<std::uint32_t> functions;    // EAT values, indexed by ordinal - ordinalBase
    std::vector<std::string> forwarders;     // parallel to functions; empty when not forwarded
    std::vector<std::string> names;          // parallel to functions; first name, empty when exported by ordinal only
    std::vector<std::pair<std::string, std::uint32_t>> byName; // sorted by name, value is the function index

    [[nodiscard]] std::optional<std::uint32_t> indexOfName(std::string_view name) const;
    [[nodiscard]] std::optional<std::uint32_t> indexOfOrdinal(std::uint32_t ordinal) const;
    [[nodiscard]] bool empty() const { return functions.empty(); }
};

struct RuntimeFunction {
    std::uint32_t begin = 0;
    std::uint32_t end = 0;
};

// A PE held in image layout: every section at its RVA, SizeOfImage bytes.
// The scanner builds one from the file on disk (the reference) and parses the
// headers of the live module the same way. Everything is bounds checked; a
// malformed or truncated image yields empty tables, never a read past the end.
class PeImage {
public:
    // Lays a PE file out as the loader would, without relocations applied.
    [[nodiscard]] static std::optional<PeImage> fromFile(std::span<const std::uint8_t> file, std::string* error = nullptr);

    // Takes bytes that are already in image layout (a live module's pages, or
    // a synthetic image in a test).
    [[nodiscard]] static std::optional<PeImage> fromImage(std::vector<std::uint8_t> image, std::string* error = nullptr);

    [[nodiscard]] bool is64() const { return is64_; }
    [[nodiscard]] std::uint16_t machine() const { return machine_; }
    // The preferred base from the header, and the base relocate() last
    // applied fixups for (the preferred base until then).
    [[nodiscard]] std::uint64_t imageBase() const { return imageBase_; }
    [[nodiscard]] std::uint64_t loadedBase() const { return loadedBase_; }
    [[nodiscard]] std::uint32_t sizeOfImage() const { return sizeOfImage_; }
    [[nodiscard]] std::uint32_t sizeOfHeaders() const { return sizeOfHeaders_; }
    [[nodiscard]] std::uint32_t entryPoint() const { return entryPoint_; }
    [[nodiscard]] std::uint32_t timeDateStamp() const { return timeDateStamp_; }
    [[nodiscard]] std::uint32_t checkSum() const { return checkSum_; }
    [[nodiscard]] bool isDotNet() const { return directory(14).second != 0; }
    [[nodiscard]] const std::vector<Section>& sections() const { return sections_; }
    [[nodiscard]] std::pair<std::uint32_t, std::uint32_t> directory(unsigned index) const;

    [[nodiscard]] std::span<const std::uint8_t> bytes() const { return image_; }
    [[nodiscard]] std::span<std::uint8_t> mutableBytes() { return image_; }

    // The section that holds `rva`, or nullptr.
    [[nodiscard]] const Section* sectionAt(std::uint32_t rva) const;

    // Bounds-checked reads in image layout.
    [[nodiscard]] std::optional<std::uint32_t> read32(std::uint32_t rva) const;
    [[nodiscard]] std::optional<std::uint64_t> read64(std::uint32_t rva) const;
    [[nodiscard]] std::optional<std::uint64_t> readPointer(std::uint32_t rva) const;
    [[nodiscard]] std::string readString(std::uint32_t rva, std::size_t maxLength = 512) const;

    // Applies base relocations for a load at `actualBase`. Returns the number
    // of fixups applied.
    std::size_t relocate(std::uint64_t actualBase, std::string* error = nullptr);

    [[nodiscard]] std::vector<ImportModule> imports() const;
    [[nodiscard]] ExportTable exports() const;
    // x64 .pdata, sorted by begin. Empty on x86.
    [[nodiscard]] std::vector<RuntimeFunction> runtimeFunctions() const;

    // RVA ranges the loader or the C runtime writes after mapping: the IAT and
    // delay-load IAT, the delay-load module handle slots, the CFG and XFG
    // dispatch pointers, the security cookie and the TLS index. A few linkers
    // place these inside an executable section; the code diff skips them and
    // the IAT check covers the import slots instead.
    [[nodiscard]] std::vector<RvaRange> loaderWrittenRanges() const;

    // True when the load configuration names a dynamic value relocation table.
    // Windows can rewrite code in such modules at load time.
    [[nodiscard]] bool hasDynamicRelocations() const;

private:
    PeImage() = default;
    bool parseHeaders(std::string* error);

    std::vector<std::uint8_t> image_;
    std::vector<Section> sections_;
    bool is64_ = false;
    std::uint16_t machine_ = 0;
    std::uint64_t imageBase_ = 0;
    std::uint64_t loadedBase_ = 0; // imageBase_ until relocate() moves it
    std::uint32_t sizeOfImage_ = 0;
    std::uint32_t sizeOfHeaders_ = 0;
    std::uint32_t entryPoint_ = 0;
    std::uint32_t timeDateStamp_ = 0;
    std::uint32_t checkSum_ = 0;
    std::uint32_t ntOffset_ = 0;
    std::uint32_t dataDirectoryOffset_ = 0;
    std::uint32_t numberOfDirectories_ = 0;
};

// Lower-case ASCII copy, for module and DLL name comparisons.
[[nodiscard]] std::string toLower(std::string_view text);

} // namespace hookscan
