#include "core/PeImage.h"

#include "core/Relocations.h"

#include <algorithm>
#include <cstring>

namespace hookscan {

namespace {

constexpr std::uint32_t kScnCntCode = 0x00000020;
constexpr std::uint32_t kScnMemExecute = 0x20000000;
constexpr std::uint32_t kScnMemWrite = 0x80000000;

// Images larger than this are refused rather than allocated. The largest
// system DLLs are a few hundred MiB; a bogus SizeOfImage should not take 4 GiB.
constexpr std::uint32_t kMaxImageSize = 0x40000000;

constexpr unsigned kDirExport = 0;
constexpr unsigned kDirImport = 1;
constexpr unsigned kDirException = 3;
constexpr unsigned kDirReloc = 5;
constexpr unsigned kDirTls = 9;
constexpr unsigned kDirLoadConfig = 10;
constexpr unsigned kDirIat = 12;
constexpr unsigned kDirDelayImport = 13;

// Offsets of the load configuration fields the loader or CRT writes through.
// Written out rather than taken from winnt.h, whose newest fields depend on the
// SDK version the build happens to find.
struct LoadConfigLayout {
    std::uint32_t securityCookie;
    std::uint32_t guardCfCheck;
    std::uint32_t guardCfDispatch;
    std::uint32_t dynamicValueRelocTable;
    std::uint32_t guardRfFailureRoutinePointer;
    std::uint32_t dynamicValueRelocTableOffset;
    std::uint32_t dynamicValueRelocTableSection;
    std::uint32_t guardRfVerifyStackPointer;
    std::uint32_t guardXfgCheck;
    std::uint32_t guardXfgDispatch;
    std::uint32_t guardXfgTableDispatch;
    std::uint32_t castGuardFailureMode;
    std::uint32_t guardMemcpy;
};
constexpr LoadConfigLayout kLoadConfig32{60, 72, 76, 120, 132, 136, 140, 144, 172, 176, 180, 184, 188};
constexpr LoadConfigLayout kLoadConfig64{88, 112, 120, 192, 216, 224, 228, 232, 280, 288, 296, 304, 312};

template <typename T>
std::optional<T> readAt(std::span<const std::uint8_t> bytes, std::uint64_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < sizeof(T)) {
        return std::nullopt;
    }
    T value;
    std::memcpy(&value, bytes.data() + offset, sizeof(T));
    return value;
}

std::uint32_t alignUp(std::uint32_t value, std::uint32_t alignment) {
    if (alignment == 0) {
        return value;
    }
    const std::uint64_t aligned = (static_cast<std::uint64_t>(value) + alignment - 1) / alignment * alignment;
    return aligned > 0xFFFFFFFFull ? 0xFFFFFFFFu : static_cast<std::uint32_t>(aligned);
}

void fail(std::string* error, const char* message) {
    if (error) {
        *error = message;
    }
}

} // namespace

std::string toLower(std::string_view text) {
    std::string out(text);
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return out;
}

bool Section::executable() const {
    return (characteristics & (kScnMemExecute | kScnCntCode)) != 0;
}

bool Section::writable() const {
    return (characteristics & kScnMemWrite) != 0;
}

std::optional<std::uint32_t> ExportTable::indexOfName(std::string_view name) const {
    const auto it = std::lower_bound(byName.begin(), byName.end(), name, [](const auto& entry, std::string_view key) { return entry.first < key; });
    if (it == byName.end() || it->first != name) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<std::uint32_t> ExportTable::indexOfOrdinal(std::uint32_t ordinal) const {
    if (ordinal < ordinalBase || ordinal - ordinalBase >= functions.size()) {
        return std::nullopt;
    }
    return ordinal - ordinalBase;
}

bool PeImage::parseHeaders(std::string* error) {
    const std::span<const std::uint8_t> b = image_;
    if (readAt<std::uint16_t>(b, 0).value_or(0) != 0x5A4D) {
        fail(error, "no MZ header");
        return false;
    }
    ntOffset_ = readAt<std::uint32_t>(b, 0x3C).value_or(0xFFFFFFFF);
    if (readAt<std::uint32_t>(b, ntOffset_).value_or(0) != 0x00004550) {
        fail(error, "no PE signature");
        return false;
    }
    const std::uint64_t fileHeader = static_cast<std::uint64_t>(ntOffset_) + 4;
    const std::uint64_t optional = fileHeader + 20;
    const auto machine = readAt<std::uint16_t>(b, fileHeader);
    const auto sectionCount = readAt<std::uint16_t>(b, fileHeader + 2);
    const auto timeDateStamp = readAt<std::uint32_t>(b, fileHeader + 4);
    const auto optionalSize = readAt<std::uint16_t>(b, fileHeader + 16);
    const auto magic = readAt<std::uint16_t>(b, optional);
    if (!machine || !sectionCount || !optionalSize || !magic || !timeDateStamp) {
        fail(error, "truncated file header");
        return false;
    }
    if (*magic != 0x10B && *magic != 0x20B) {
        fail(error, "unknown optional header magic");
        return false;
    }
    is64_ = *magic == 0x20B;
    machine_ = *machine;
    timeDateStamp_ = *timeDateStamp;

    const auto entryPoint = readAt<std::uint32_t>(b, optional + 16);
    std::optional<std::uint64_t> imageBase = readAt<std::uint64_t>(b, optional + 24);
    if (!is64_) {
        const auto base32 = readAt<std::uint32_t>(b, optional + 28);
        imageBase = base32 ? std::optional<std::uint64_t>(*base32) : std::nullopt;
    }
    const auto sizeOfImage = readAt<std::uint32_t>(b, optional + 56);
    const auto sizeOfHeaders = readAt<std::uint32_t>(b, optional + 60);
    const auto checkSum = readAt<std::uint32_t>(b, optional + 64);
    const std::uint64_t rvaCountOffset = optional + (is64_ ? 108 : 92);
    const auto numberOfDirectories = readAt<std::uint32_t>(b, rvaCountOffset);
    if (!entryPoint || !imageBase || !sizeOfImage || !sizeOfHeaders || !checkSum || !numberOfDirectories) {
        fail(error, "truncated optional header");
        return false;
    }
    if (*sizeOfImage == 0 || *sizeOfImage > kMaxImageSize) {
        fail(error, "implausible SizeOfImage");
        return false;
    }
    entryPoint_ = *entryPoint;
    imageBase_ = *imageBase;
    loadedBase_ = imageBase_;
    sizeOfImage_ = *sizeOfImage;
    sizeOfHeaders_ = *sizeOfHeaders;
    checkSum_ = *checkSum;
    dataDirectoryOffset_ = static_cast<std::uint32_t>(rvaCountOffset + 4);
    // Directories past the optional header's declared size are not there.
    const std::uint64_t directoryBytes = optional + *optionalSize > dataDirectoryOffset_ ? optional + *optionalSize - dataDirectoryOffset_ : 0;
    numberOfDirectories_ = static_cast<std::uint32_t>(std::min<std::uint64_t>({*numberOfDirectories, 16, directoryBytes / 8}));

    sections_.clear();
    const std::uint64_t sectionTable = optional + *optionalSize;
    for (std::uint32_t i = 0; i < *sectionCount; ++i) {
        const std::uint64_t at = sectionTable + static_cast<std::uint64_t>(i) * 40;
        if (at > b.size() || b.size() - at < 40) {
            fail(error, "truncated section table");
            return false;
        }
        Section s;
        const char* name = reinterpret_cast<const char*>(b.data() + at);
        s.name.assign(name, strnlen(name, 8));
        const auto virtualSize = *readAt<std::uint32_t>(b, at + 8);
        s.virtualAddress = *readAt<std::uint32_t>(b, at + 12);
        s.rawSize = *readAt<std::uint32_t>(b, at + 16);
        s.rawOffset = *readAt<std::uint32_t>(b, at + 20);
        s.characteristics = *readAt<std::uint32_t>(b, at + 36);
        s.virtualSize = virtualSize != 0 ? virtualSize : s.rawSize;
        sections_.push_back(std::move(s));
    }
    return true;
}

std::optional<PeImage> PeImage::fromFile(std::span<const std::uint8_t> file, std::string* error) {
    PeImage raw;
    raw.image_.assign(file.begin(), file.end());
    if (!raw.parseHeaders(error)) {
        return std::nullopt;
    }
    const auto sectionAlignment = readAt<std::uint32_t>(file, raw.ntOffset_ + 4 + 20 + 32).value_or(0x1000);

    PeImage mapped;
    mapped.image_.assign(raw.sizeOfImage_, 0);
    const std::size_t headerBytes = std::min<std::size_t>({raw.sizeOfHeaders_, file.size(), raw.sizeOfImage_});
    std::memcpy(mapped.image_.data(), file.data(), headerBytes);
    for (const Section& s : raw.sections_) {
        if (s.virtualAddress >= raw.sizeOfImage_ || s.rawOffset >= file.size()) {
            continue;
        }
        std::uint64_t count = std::min<std::uint64_t>(s.rawSize, alignUp(s.virtualSize, sectionAlignment));
        count = std::min<std::uint64_t>(count, file.size() - s.rawOffset);
        count = std::min<std::uint64_t>(count, raw.sizeOfImage_ - s.virtualAddress);
        std::memcpy(mapped.image_.data() + s.virtualAddress, file.data() + s.rawOffset, static_cast<std::size_t>(count));
    }
    if (!mapped.parseHeaders(error)) {
        return std::nullopt;
    }
    return mapped;
}

std::optional<PeImage> PeImage::fromImage(std::vector<std::uint8_t> image, std::string* error) {
    PeImage pe;
    pe.image_ = std::move(image);
    if (!pe.parseHeaders(error)) {
        return std::nullopt;
    }
    return pe;
}

std::pair<std::uint32_t, std::uint32_t> PeImage::directory(unsigned index) const {
    if (index >= numberOfDirectories_) {
        return {0, 0};
    }
    const std::uint64_t at = static_cast<std::uint64_t>(dataDirectoryOffset_) + index * 8ull;
    return {readAt<std::uint32_t>(image_, at).value_or(0), readAt<std::uint32_t>(image_, at + 4).value_or(0)};
}

const Section* PeImage::sectionAt(std::uint32_t rva) const {
    for (const Section& s : sections_) {
        if (rva >= s.virtualAddress && rva - s.virtualAddress < s.virtualSize) {
            return &s;
        }
    }
    return nullptr;
}

std::optional<std::uint32_t> PeImage::read32(std::uint32_t rva) const {
    return readAt<std::uint32_t>(image_, rva);
}

std::optional<std::uint64_t> PeImage::read64(std::uint32_t rva) const {
    return readAt<std::uint64_t>(image_, rva);
}

std::optional<std::uint64_t> PeImage::readPointer(std::uint32_t rva) const {
    if (is64_) {
        return read64(rva);
    }
    const auto v = read32(rva);
    return v ? std::optional<std::uint64_t>(*v) : std::nullopt;
}

std::string PeImage::readString(std::uint32_t rva, std::size_t maxLength) const {
    std::string out;
    for (std::size_t i = 0; i < maxLength; ++i) {
        const std::uint64_t at = static_cast<std::uint64_t>(rva) + i;
        if (at >= image_.size() || image_[static_cast<std::size_t>(at)] == 0) {
            break;
        }
        out.push_back(static_cast<char>(image_[static_cast<std::size_t>(at)]));
    }
    return out;
}

std::size_t PeImage::relocate(std::uint64_t actualBase, std::string* error) {
    const auto [rva, size] = directory(kDirReloc);
    const auto delta = static_cast<std::int64_t>(actualBase - imageBase_);
    const RelocationStats stats = applyRelocations(image_, rva, size, delta);
    loadedBase_ = actualBase;
    if (stats.malformed) {
        fail(error, "the relocation table is malformed; fixups after the bad block were not applied");
    }
    return stats.applied;
}

std::vector<ImportModule> PeImage::imports() const {
    std::vector<ImportModule> out;
    const std::uint32_t pointerSize = is64_ ? 8 : 4;
    const std::uint64_t ordinalFlag = is64_ ? 0x8000000000000000ull : 0x80000000ull;

    auto readThunks = [&](ImportModule& module, std::uint32_t nameTable, std::uint32_t addressTable) {
        for (std::uint32_t i = 0; i < 0x10000; ++i) {
            const auto thunk = readPointer(nameTable + i * pointerSize);
            if (!thunk || *thunk == 0) {
                break;
            }
            ImportEntry entry;
            entry.iatRva = addressTable + i * pointerSize;
            if (*thunk & ordinalFlag) {
                entry.byOrdinal = true;
                entry.ordinal = static_cast<std::uint16_t>(*thunk & 0xFFFF);
            } else {
                entry.name = readString(static_cast<std::uint32_t>(*thunk) + 2);
            }
            module.entries.push_back(std::move(entry));
        }
    };

    const auto [importRva, importSize] = directory(kDirImport);
    if (importRva != 0 && importSize != 0) {
        for (std::uint32_t i = 0; i < 0x4000; ++i) {
            const std::uint32_t at = importRva + i * 20;
            const auto originalFirstThunk = read32(at);
            const auto timeDateStamp = read32(at + 4);
            const auto name = read32(at + 12);
            const auto firstThunk = read32(at + 16);
            if (!originalFirstThunk || !name || !firstThunk || (*name == 0 && *firstThunk == 0)) {
                break;
            }
            ImportModule module;
            module.dll = readString(*name, 260);
            // Without an import name table a bound IAT holds addresses, not
            // names, and there is nothing to check the live values against.
            if (*originalFirstThunk == 0 && *timeDateStamp != 0) {
                out.push_back(std::move(module));
                continue;
            }
            readThunks(module, *originalFirstThunk != 0 ? *originalFirstThunk : *firstThunk, *firstThunk);
            out.push_back(std::move(module));
        }
    }

    const auto [delayRva, delaySize] = directory(kDirDelayImport);
    if (delayRva != 0 && delaySize != 0) {
        for (std::uint32_t i = 0; i < 0x4000; ++i) {
            const std::uint32_t at = delayRva + i * 32;
            const auto attributes = read32(at);
            const auto name = read32(at + 4);
            const auto iat = read32(at + 12);
            const auto nameTable = read32(at + 16);
            if (!attributes || !name || !iat || !nameTable || *name == 0) {
                break;
            }
            // Attribute bit 0 clear is the Visual C++ 6 layout, which stores
            // VAs. Nothing current emits it; skip rather than guess.
            if ((*attributes & 1) == 0) {
                continue;
            }
            ImportModule module;
            module.dll = readString(*name, 260);
            module.delayLoad = true;
            readThunks(module, *nameTable, *iat);
            out.push_back(std::move(module));
        }
    }
    return out;
}

ExportTable PeImage::exports() const {
    ExportTable table;
    const auto [rva, size] = directory(kDirExport);
    if (rva == 0 || size == 0) {
        return table;
    }
    const auto base = read32(rva + 16);
    const auto functionCount = read32(rva + 20);
    const auto nameCount = read32(rva + 24);
    const auto functionsRva = read32(rva + 28);
    const auto namesRva = read32(rva + 32);
    const auto ordinalsRva = read32(rva + 36);
    if (!base || !functionCount || !nameCount || !functionsRva || !namesRva || !ordinalsRva) {
        return table;
    }
    if (*functionCount > 0x100000 || *nameCount > 0x100000 ||
        static_cast<std::uint64_t>(*functionsRva) + static_cast<std::uint64_t>(*functionCount) * 4 > image_.size()) {
        return table;
    }
    table.ordinalBase = *base;
    table.eatRva = *functionsRva;
    table.directoryRva = rva;
    table.directorySize = size;
    table.functions.resize(*functionCount);
    table.forwarders.resize(*functionCount);
    table.names.resize(*functionCount);
    for (std::uint32_t i = 0; i < *functionCount; ++i) {
        const std::uint32_t value = *read32(*functionsRva + i * 4);
        table.functions[i] = value;
        if (value >= rva && value - rva < size) {
            table.forwarders[i] = readString(value, 256);
        }
    }
    for (std::uint32_t i = 0; i < *nameCount; ++i) {
        const auto nameRva = read32(*namesRva + i * 4);
        const auto ordinalBytes = readAt<std::uint16_t>(image_, static_cast<std::uint64_t>(*ordinalsRva) + i * 2ull);
        if (!nameRva || !ordinalBytes || *ordinalBytes >= *functionCount) {
            continue;
        }
        std::string name = readString(*nameRva, 512);
        if (table.names[*ordinalBytes].empty()) {
            table.names[*ordinalBytes] = name;
        }
        table.byName.emplace_back(std::move(name), *ordinalBytes);
    }
    std::sort(table.byName.begin(), table.byName.end());
    return table;
}

std::vector<RuntimeFunction> PeImage::runtimeFunctions() const {
    std::vector<RuntimeFunction> out;
    if (!is64_) {
        return out;
    }
    const auto [rva, size] = directory(kDirException);
    for (std::uint32_t at = rva; rva != 0 && at + 12 <= static_cast<std::uint64_t>(rva) + size; at += 12) {
        const auto begin = read32(at);
        const auto end = read32(at + 4);
        if (!begin || !end) {
            break;
        }
        if (*end > *begin) {
            out.push_back({*begin, *end});
        }
    }
    std::sort(out.begin(), out.end(), [](const RuntimeFunction& a, const RuntimeFunction& b) { return a.begin < b.begin; });
    return out;
}

std::vector<RvaRange> PeImage::loaderWrittenRanges() const {
    std::vector<RvaRange> out;
    const std::uint32_t pointerSize = is64_ ? 8 : 4;

    auto addVa = [&](std::uint64_t va, std::uint32_t length) {
        if (va == 0 || va < loadedBase_) {
            return;
        }
        const std::uint64_t rva = va - loadedBase_;
        if (rva < sizeOfImage_ && sizeOfImage_ - rva >= length) {
            out.push_back({static_cast<std::uint32_t>(rva), static_cast<std::uint32_t>(rva + length)});
        }
    };

    const auto [iatRva, iatSize] = directory(kDirIat);
    if (iatRva != 0 && iatSize != 0) {
        out.push_back({iatRva, iatRva + iatSize});
    }
    for (const ImportModule& module : imports()) {
        if (!module.entries.empty()) {
            // Include the null terminator slot.
            out.push_back({module.entries.front().iatRva, module.entries.back().iatRva + 2 * pointerSize});
        }
    }
    const auto [delayRva, delaySize] = directory(kDirDelayImport);
    for (std::uint32_t at = delayRva; delayRva != 0 && at + 32 <= static_cast<std::uint64_t>(delayRva) + delaySize; at += 32) {
        const auto attributes = read32(at);
        const auto moduleHandle = read32(at + 8);
        if (!attributes || !moduleHandle || read32(at + 4).value_or(0) == 0) {
            break;
        }
        if ((*attributes & 1) != 0 && *moduleHandle != 0) {
            out.push_back({*moduleHandle, *moduleHandle + pointerSize});
        }
    }

    const auto [configRva, configSize] = directory(kDirLoadConfig);
    if (configRva != 0) {
        const std::uint32_t declared = read32(configRva).value_or(0);
        const std::uint32_t available = std::max(declared, configSize);
        const LoadConfigLayout& layout = is64_ ? kLoadConfig64 : kLoadConfig32;
        for (const std::uint32_t field :
             {layout.securityCookie, layout.guardCfCheck, layout.guardCfDispatch, layout.guardRfFailureRoutinePointer,
              layout.guardRfVerifyStackPointer, layout.guardXfgCheck, layout.guardXfgDispatch, layout.guardXfgTableDispatch,
              layout.castGuardFailureMode, layout.guardMemcpy}) {
            if (field + pointerSize <= declared && field + pointerSize <= available) {
                addVa(readPointer(configRva + field).value_or(0), pointerSize);
            }
        }
    }

    const auto [tlsRva, tlsSize] = directory(kDirTls);
    if (tlsRva != 0 && tlsSize != 0) {
        addVa(readPointer(tlsRva + 2 * pointerSize).value_or(0), 4);
    }

    std::sort(out.begin(), out.end(), [](const RvaRange& a, const RvaRange& b) { return a.begin < b.begin; });
    return out;
}

bool PeImage::hasDynamicRelocations() const {
    const auto [configRva, configSize] = directory(kDirLoadConfig);
    if (configRva == 0 || configSize == 0) {
        return false;
    }
    const std::uint32_t declared = read32(configRva).value_or(0);
    const LoadConfigLayout& layout = is64_ ? kLoadConfig64 : kLoadConfig32;
    const std::uint32_t pointerSize = is64_ ? 8 : 4;
    if (layout.dynamicValueRelocTable + pointerSize <= declared && readPointer(configRva + layout.dynamicValueRelocTable).value_or(0) != 0) {
        return true;
    }
    if (layout.dynamicValueRelocTableSection + 2 <= declared) {
        const auto offset = read32(configRva + layout.dynamicValueRelocTableOffset).value_or(0);
        const auto section = readAt<std::uint16_t>(image_, static_cast<std::uint64_t>(configRva) + layout.dynamicValueRelocTableSection).value_or(0);
        return offset != 0 && section != 0;
    }
    return false;
}

} // namespace hookscan
