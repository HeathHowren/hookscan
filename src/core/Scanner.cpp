#include "core/Scanner.h"

#include "core/ApiSet.h"
#include "core/Diff.h"
#include "core/PeImage.h"
#include "core/Process.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <set>
#include <unordered_map>

namespace hookscan {

namespace {

std::string hex(std::uint64_t value) {
    char text[24];
    std::snprintf(text, sizeof(text), "0x%llX", static_cast<unsigned long long>(value));
    return text;
}

std::string fileName(const std::string& path) {
    const auto slash = path.find_last_of("\\/");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

// Modules that change their own code as a matter of course. A patch in one
// of them that does not jump elsewhere is still reported, with this reason.
bool isSelfPatchingRuntime(const std::string& lowerName) {
    return lowerName == "clr.dll" || lowerName == "coreclr.dll" || lowerName == "mscorwks.dll";
}

// The application compatibility shim engine and its shim DLLs redirect
// imports of programs Windows has compatibility fixes for.
bool isShimEngine(const std::string& lowerName) {
    return lowerName == "apphelp.dll" || lowerName.starts_with("aclayers") || lowerName.starts_with("acgenral") || lowerName.starts_with("acspecfc") ||
           lowerName.starts_with("acxtrnal") || lowerName.starts_with("acwinrt");
}

struct ModuleState {
    ModuleInfo info;
    std::string lowerName;
    bool attempted = false;
    std::optional<PeImage> reference; // the file, laid out and relocated to this module's base
    std::string path;                 // the mapped file, as a DOS path where possible
    std::string problem;              // why there is no reference
    bool unbacked = false;            // no file mapping at the module base
    bool fileMissing = false;         // a mapping, but the file cannot be found any more
    ExportTable exports;
    std::unordered_map<std::uint32_t, std::string> exportNames; // RVA -> first name
};

class Scan {
public:
    Scan(const Process& process, const ScanOptions& options)
        : process_(process), options_(options), disassembler_(Process::bitness()), apiSets_(ApiSetResolver::system()) {}

    std::optional<ScanResult> run(std::string* error);

private:
    ModuleState& load(std::size_t index);
    std::optional<std::size_t> containing(std::uint64_t address) const;
    AddressInfo describe(std::uint64_t address);
    std::vector<std::uint64_t> resolveExport(const std::string& dll, const std::string& name, std::optional<std::uint32_t> ordinal,
                                             const std::string& importer, int depth);

    bool checkHeaders(ModuleState& m);
    void checkCode(ModuleState& m);
    void checkImports(ModuleState& m);
    void checkExports(ModuleState& m);
    void checkMemory();
    bool isWow64Layer(std::uint64_t base, const std::string& path) const;

    void note(std::string text) { result_.notes.push_back(std::move(text)); }
    std::uint32_t pointerSize() const { return Process::bitness() == Bitness::X64 ? 8 : 4; }

    const Process& process_;
    const ScanOptions& options_;
    Disassembler disassembler_;
    const ApiSetResolver& apiSets_;
    ScanResult result_;
    std::vector<ModuleState> modules_;                                // loader order
    std::vector<std::size_t> byBase_;                                 // indices sorted by base
    std::unordered_map<std::string, std::vector<std::size_t>> byName_; // lower-case base name -> indices
};

ModuleState& Scan::load(std::size_t index) {
    ModuleState& m = modules_[index];
    if (m.attempted) {
        return m;
    }
    m.attempted = true;

    const auto mapped = process_.mappedFile(m.info.base);
    if (!mapped) {
        m.unbacked = true;
        const auto region = process_.query(m.info.base);
        m.problem = region && !region->isImage() ? "the module's memory is not an image mapping; no file backs it"
                                                 : "no file is mapped at the module base";
        return m;
    }
    m.path = utf8(devicePathToDos(*mapped));

    unsigned long code = 0;
    const auto bytes = readDeviceFile(*mapped, &code);
    if (!bytes) {
        m.fileMissing = code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND || code == ERROR_DELETE_PENDING;
        m.problem = "cannot read " + m.path + ": " + win32ErrorText(code);
        return m;
    }
    std::string parseError;
    auto pe = PeImage::fromFile(*bytes, &parseError);
    if (!pe) {
        m.problem = "cannot parse " + m.path + ": " + parseError;
        return m;
    }
    std::string relocationError;
    pe->relocate(m.info.base, &relocationError);
    if (!relocationError.empty()) {
        note(m.info.name + ": " + relocationError);
    }
    m.exports = pe->exports();
    for (std::size_t i = 0; i < m.exports.functions.size(); ++i) {
        if (!m.exports.names[i].empty() && m.exports.forwarders[i].empty()) {
            m.exportNames.emplace(m.exports.functions[i], m.exports.names[i]);
        }
    }
    m.reference = std::move(pe);
    return m;
}

std::optional<std::size_t> Scan::containing(std::uint64_t address) const {
    auto it = std::upper_bound(byBase_.begin(), byBase_.end(), address,
                               [this](std::uint64_t a, std::size_t index) { return a < modules_[index].info.base; });
    if (it == byBase_.begin()) {
        return std::nullopt;
    }
    --it;
    const ModuleInfo& info = modules_[*it].info;
    if (address - info.base < info.size) {
        return *it;
    }
    return std::nullopt;
}

AddressInfo Scan::describe(std::uint64_t address) {
    AddressInfo a;
    a.address = address;
    if (const auto index = containing(address)) {
        ModuleState& m = load(*index);
        a.module = m.info.name;
        a.offset = address - m.info.base;
        if (const auto it = m.exportNames.find(static_cast<std::uint32_t>(a.offset)); it != m.exportNames.end()) {
            a.symbol = it->second;
        }
        return a;
    }
    const auto region = process_.query(address);
    if (!region) {
        a.memory = "unknown";
    } else if (region->isFree()) {
        a.memory = "unallocated";
    } else if (region->isImage()) {
        a.memory = "unlisted image";
        if (const auto file = process_.mappedFile(address)) {
            a.file = utf8(devicePathToDos(*file));
        }
    } else if (region->isMapped()) {
        a.memory = "mapped memory";
    } else {
        a.memory = "private memory";
    }
    return a;
}

std::vector<std::uint64_t> Scan::resolveExport(const std::string& dll, const std::string& name, std::optional<std::uint32_t> ordinal,
                                               const std::string& importer, int depth) {
    std::vector<std::uint64_t> out;
    if (depth > 8) {
        return out;
    }
    std::string target = toLower(dll);
    if (ApiSetResolver::isApiSetName(target)) {
        const auto host = apiSets_.resolve(target, importer);
        if (!host || host->empty()) {
            return out;
        }
        target = *host;
    }
    auto it = byName_.find(target);
    if (it == byName_.end() && target.find('.') == std::string::npos) {
        it = byName_.find(target + ".dll");
    }
    if (it == byName_.end()) {
        return out;
    }

    for (const std::size_t index : it->second) {
        ModuleState& m = load(index);
        if (!m.reference) {
            continue;
        }
        const auto slot = ordinal ? m.exports.indexOfOrdinal(*ordinal) : m.exports.indexOfName(name);
        if (!slot) {
            continue;
        }
        const std::string& forwarder = m.exports.forwarders[*slot];
        if (forwarder.empty()) {
            out.push_back(m.info.base + m.exports.functions[*slot]);
            continue;
        }
        // "NTDLL.RtlAllocateHeap", "api-ms-win-core-x-l1-1-0.Func" or "DLL.#12"
        const auto dot = forwarder.rfind('.');
        if (dot == std::string::npos || dot + 1 >= forwarder.size()) {
            continue;
        }
        std::string forwardDll = forwarder.substr(0, dot);
        if (!toLower(forwardDll).ends_with(".dll")) {
            forwardDll += ".dll";
        }
        const std::string forwardName = forwarder.substr(dot + 1);
        std::vector<std::uint64_t> next;
        if (forwardName[0] == '#') {
            const auto forwardOrdinal = static_cast<std::uint32_t>(std::strtoul(forwardName.c_str() + 1, nullptr, 10));
            next = resolveExport(forwardDll, {}, forwardOrdinal, m.lowerName, depth + 1);
        } else {
            next = resolveExport(forwardDll, forwardName, std::nullopt, m.lowerName, depth + 1);
        }
        out.insert(out.end(), next.begin(), next.end());
    }
    return out;
}

bool Scan::checkHeaders(ModuleState& m) {
    const PeImage& file = *m.reference;
    const std::uint32_t headerSize = std::clamp<std::uint32_t>(file.sizeOfHeaders(), 0x200, 0x10000);
    std::vector<std::uint8_t> bytes(std::min(headerSize, m.info.size));
    if (!process_.read(m.info.base, bytes.data(), bytes.size())) {
        note(m.info.name + ": the headers in memory cannot be read; code and tables not compared");
        return false;
    }

    auto mismatch = [&](std::string detail) {
        Finding f;
        f.kind = FindingKind::ImageMismatch;
        f.module = m.info.name;
        f.moduleBase = m.info.base;
        f.address = m.info.base;
        f.size = m.info.size;
        f.path = m.path;
        f.detail = std::move(detail);
        result_.findings.push_back(std::move(f));
        return false;
    };

    std::string error;
    const auto memory = PeImage::fromImage(std::move(bytes), &error);
    if (!memory) {
        return mismatch("the headers in memory are not a valid PE header (" + error + ")");
    }
    if (memory->is64() != file.is64()) {
        if (file.isDotNet()) {
            // The loader rewrites the optional header of an AnyCPU .NET
            // assembly it maps into a 64-bit process. Nothing to compare.
            note(m.info.name + ": an AnyCPU .NET assembly whose headers the loader rewrote; not compared");
            return false;
        }
        return mismatch("the file is " + std::string(file.is64() ? "PE32+" : "PE32") + " but memory holds " + (memory->is64() ? "PE32+" : "PE32"));
    }
    if (memory->timeDateStamp() != file.timeDateStamp()) {
        return mismatch("TimeDateStamp differs: memory " + hex(memory->timeDateStamp()) + ", file " + hex(file.timeDateStamp()));
    }
    if (memory->sizeOfImage() != file.sizeOfImage()) {
        return mismatch("SizeOfImage differs: memory " + hex(memory->sizeOfImage()) + ", file " + hex(file.sizeOfImage()));
    }
    if (memory->entryPoint() != file.entryPoint()) {
        return mismatch("AddressOfEntryPoint differs: memory " + hex(memory->entryPoint()) + ", file " + hex(file.entryPoint()));
    }
    if (memory->sections().size() != file.sections().size()) {
        return mismatch("the section count differs: memory " + std::to_string(memory->sections().size()) + ", file " +
                        std::to_string(file.sections().size()));
    }
    for (std::size_t i = 0; i < file.sections().size(); ++i) {
        const Section& a = memory->sections()[i];
        const Section& b = file.sections()[i];
        if (a.name != b.name || a.virtualAddress != b.virtualAddress || a.virtualSize != b.virtualSize) {
            return mismatch("section " + std::to_string(i + 1) + " differs: memory " + a.name + " at " + hex(a.virtualAddress) + ", file " + b.name +
                            " at " + hex(b.virtualAddress));
        }
    }
    return true;
}

void Scan::checkCode(ModuleState& m) {
    const PeImage& file = *m.reference;
    const auto functions = file.runtimeFunctions();
    const bool dynamicRelocations = file.hasDynamicRelocations();

    std::vector<RvaRange> skipped = file.loaderWrittenRanges();
    if (!m.exports.empty()) {
        // The EAT check covers these; a few old linkers merge .edata into .text.
        skipped.push_back({m.exports.eatRva, m.exports.eatRva + static_cast<std::uint32_t>(m.exports.functions.size() * 4)});
    }

    for (const Section& section : file.sections()) {
        if (!section.executable() || section.virtualSize == 0 || section.virtualAddress >= file.sizeOfImage()) {
            continue;
        }
        if (section.writable() && !options_.includeWritable) {
            note(m.info.name + ": section " + section.name + " is writable and executable; not compared (--include-writable compares it)");
            continue;
        }
        const std::uint32_t size = std::min(section.virtualSize, file.sizeOfImage() - section.virtualAddress);
        const std::uint64_t sectionAddress = m.info.base + section.virtualAddress;

        std::vector<ByteRange> ignore;
        const std::vector<std::uint8_t> live = process_.readRange(sectionAddress, size, ignore);
        std::size_t unreadable = 0;
        for (const ByteRange& r : ignore) {
            unreadable += r.end - r.begin;
        }
        if (unreadable != 0) {
            note(m.info.name + ": " + std::to_string(unreadable) + " bytes of " + section.name + " could not be read and were not compared");
        }
        for (const RvaRange& r : skipped) {
            const std::uint32_t begin = std::max(r.begin, section.virtualAddress);
            const std::uint32_t end = std::min(r.end, section.virtualAddress + size);
            if (begin < end) {
                ignore.push_back({begin - section.virtualAddress, end - section.virtualAddress});
            }
        }

        const auto expected = file.bytes().subspan(section.virtualAddress, size);
        const CodeView originalView{expected, sectionAddress};
        const CodeView liveView{live, sectionAddress};
        auto regions = diffRegions(expected, live, ignore, options_.mergeGap);
        if (regions.size() > options_.maxRegionsPerSection) {
            note(m.info.name + ": " + std::to_string(regions.size()) + " changed regions in " + section.name + "; only the first " +
                 std::to_string(options_.maxRegionsPerSection) + " are reported. The module may be packed or modify its own code");
            regions.resize(options_.maxRegionsPerSection);
        }

        std::uint64_t coveredTo = 0;
        for (const ByteRange& r : regions) {
            std::uint64_t begin = sectionAddress + r.begin;
            const std::uint64_t end = sectionAddress + r.end;
            if (end <= coveredTo) {
                continue; // decoded as part of the previous patch
            }

            std::optional<std::uint64_t> functionBegin;
            const std::uint32_t rva = section.virtualAddress + r.begin;
            auto fn = std::upper_bound(functions.begin(), functions.end(), rva, [](std::uint32_t v, const RuntimeFunction& f) { return v < f.begin; });
            if (fn != functions.begin() && rva < std::prev(fn)->end) {
                functionBegin = m.info.base + std::prev(fn)->begin;
            }

            std::uint64_t start = disassembler_.instructionStart(originalView, liveView, begin, functionBegin);
            start = std::max(start, coveredTo);
            const PatchAnalysis analysis = disassembler_.analyze(liveView, start, end, &process_);
            const std::uint64_t patchEnd = std::min<std::uint64_t>(analysis.end, sectionAddress + size);
            coveredTo = patchEnd;

            Finding f;
            f.kind = FindingKind::InlinePatch;
            f.module = m.info.name;
            f.moduleBase = m.info.base;
            f.address = start;
            f.size = patchEnd - start;
            f.section = section.name;
            const std::size_t from = static_cast<std::size_t>(start - sectionAddress);
            const std::size_t to = static_cast<std::size_t>(patchEnd - sectionAddress);
            f.original.assign(expected.begin() + from, expected.begin() + to);
            f.current.assign(live.begin() + from, live.begin() + to);
            f.instructions = analysis.instructions;
            f.shape = analysis.shape;
            if (analysis.target) {
                f.target = describe(*analysis.target);
            }
            if (dynamicRelocations) {
                f.detail = "this module has a dynamic relocation table, so Windows may have rewritten this code at load time";
            } else if (!f.target && f.shape != PatchShape::Breakpoint && isSelfPatchingRuntime(m.lowerName)) {
                f.detail = "no jump out of the module; the .NET runtime rewrites parts of its own code (TLS offsets, write barriers) as it starts";
            }
            result_.findings.push_back(std::move(f));
        }
    }
}

void Scan::checkImports(ModuleState& m) {
    const PeImage& file = *m.reference;
    const std::uint32_t width = pointerSize();
    std::size_t unresolved = 0;
    std::size_t unreadable = 0;

    for (const ImportModule& import : file.imports()) {
        for (const ImportEntry& entry : import.entries) {
            std::uint64_t live = 0;
            if (!process_.read(m.info.base + entry.iatRva, &live, width)) {
                ++unreadable;
                continue;
            }
            const std::uint64_t fileValue = file.readPointer(entry.iatRva).value_or(0);
            const auto candidates = resolveExport(import.dll, entry.name, entry.byOrdinal ? std::optional<std::uint32_t>(entry.ordinal) : std::nullopt,
                                                  m.lowerName, 0);
            if (std::find(candidates.begin(), candidates.end(), live) != candidates.end()) {
                continue;
            }
            if (live == fileValue) {
                if (import.delayLoad) {
                    continue; // a delay-load slot not called yet still points at its own stub
                }
                note(m.info.name + ": the imports from " + import.dll + " were never resolved (loaded with DONT_RESOLVE_DLL_REFERENCES?)");
                break;
            }
            AddressInfo target = describe(live);
            if (candidates.empty() && target.inModule()) {
                // The expected address is unknown (the DLL is not loaded, or an
                // API set has no host here, as with a delay-load that failed
                // over to the loader's stub). A slot pointing at loaded code
                // cannot be judged; one pointing anywhere else still can.
                ++unresolved;
                continue;
            }

            Finding f;
            f.kind = FindingKind::IatHook;
            f.module = m.info.name;
            f.moduleBase = m.info.base;
            f.address = m.info.base + entry.iatRva;
            f.size = width;
            f.importedModule = import.dll;
            f.function = entry.byOrdinal ? "#" + std::to_string(entry.ordinal) : entry.name;
            f.delayLoad = import.delayLoad;
            if (!candidates.empty()) {
                f.expected = describe(candidates.front());
            } else {
                f.detail = "the import could not be resolved on this system, and the slot points outside every loaded module";
            }
            f.target = std::move(target);
            if (f.target->inModule()) {
                const std::string targetModule = toLower(f.target->module);
                if (isShimEngine(targetModule)) {
                    f.detail = "the Windows application compatibility shim engine redirected this import";
                } else if (f.target->symbol == entry.name && !entry.name.empty()) {
                    f.detail = "the slot holds an export of the same name from " + f.target->module + ", not the one the import resolves to";
                }
            }
            result_.findings.push_back(std::move(f));
        }
    }
    if (unresolved != 0) {
        note(m.info.name + ": " + std::to_string(unresolved) + " imports could not be resolved and point into loaded modules; not judged");
    }
    if (unreadable != 0) {
        note(m.info.name + ": " + std::to_string(unreadable) + " import slots could not be read");
    }
}

void Scan::checkExports(ModuleState& m) {
    const ExportTable& exports = m.exports;
    if (exports.empty()) {
        return;
    }
    std::vector<std::uint32_t> live(exports.functions.size());
    if (!process_.read(m.info.base + exports.eatRva, live.data(), live.size() * 4)) {
        note(m.info.name + ": the export address table could not be read");
        return;
    }
    const std::uint32_t sizeOfImage = m.reference->sizeOfImage();
    auto absolute = [&](std::uint32_t rva) {
        std::uint64_t address = m.info.base + rva;
        if (Process::bitness() == Bitness::X86) {
            address &= 0xFFFFFFFFull; // GetProcAddress adds in 32 bits
        }
        return address;
    };

    for (std::size_t i = 0; i < live.size(); ++i) {
        if (live[i] == exports.functions[i]) {
            continue;
        }
        Finding f;
        f.kind = FindingKind::EatHook;
        f.module = m.info.name;
        f.moduleBase = m.info.base;
        f.address = m.info.base + exports.eatRva + i * 4;
        f.size = 4;
        f.function = !exports.names[i].empty() ? exports.names[i] : "#" + std::to_string(exports.ordinalBase + i);
        if (!exports.forwarders[i].empty()) {
            f.detail = "the file forwards this export to " + exports.forwarders[i];
        } else if (exports.functions[i] != 0) {
            f.expected = describe(absolute(exports.functions[i]));
        }
        f.target = describe(absolute(live[i]));
        if (live[i] >= sizeOfImage) {
            f.detail += std::string(f.detail.empty() ? "" : "; ") + "the entry points outside the module";
        }
        result_.findings.push_back(std::move(f));
    }
}

// In a 32-bit process on 64-bit Windows, the 64-bit side of WOW64 (its own
// ntdll and the wow64*.dll layer) is mapped into the process too, and only the
// 64-bit loader lists it. Some of it sits low enough for a 32-bit query to
// see. Exempt exactly that: a 64-bit image, from System32, with one of those
// names. Any other unlisted image is still reported.
bool Scan::isWow64Layer(std::uint64_t base, const std::string& path) const {
    if (Process::bitness() != Bitness::X86 || path.empty()) {
        return false;
    }
    std::uint8_t header[0x400];
    if (!process_.read(base, header, sizeof(header))) {
        return false;
    }
    std::uint32_t ntOffset = 0;
    std::memcpy(&ntOffset, header + 0x3C, 4);
    if (ntOffset > sizeof(header) - 6 || std::memcmp(header + ntOffset, "PE\0\0", 4) != 0) {
        return false;
    }
    std::uint16_t machine = 0;
    std::memcpy(&machine, header + ntOffset + 4, 2);
    if (machine != 0x8664 && machine != 0xAA64) {
        return false;
    }
    wchar_t windows[MAX_PATH];
    const UINT length = GetWindowsDirectoryW(windows, MAX_PATH);
    const std::string systemDir = toLower(utf8(std::wstring(windows, length))) + "\\system32\\";
    const std::string lower = toLower(path);
    if (!lower.starts_with(systemDir)) {
        return false;
    }
    const std::string name = lower.substr(systemDir.size());
    return name == "ntdll.dll" || name == "wow64.dll" || name == "wow64win.dll" || name == "wow64cpu.dll" || name == "wow64base.dll" ||
           name == "wow64con.dll" || name == "xtajit.dll";
}

void Scan::checkMemory() {
    std::set<std::uint64_t> listed;
    for (const ModuleState& m : modules_) {
        listed.insert(m.info.base);
    }

    struct Allocation {
        std::uint64_t base = 0;
        std::uint64_t size = 0;
        std::uint32_t type = 0;
        bool executable = false;
    };
    std::vector<Allocation> allocations;
    for (const MemoryRegion& r : process_.regions()) {
        if (r.isFree()) {
            continue;
        }
        if (allocations.empty() || allocations.back().base != r.allocationBase) {
            allocations.push_back({r.allocationBase, 0, r.type, false});
        }
        Allocation& a = allocations.back();
        a.size = r.base + r.size - a.base;
        a.executable = a.executable || r.executable();
    }

    for (const Allocation& a : allocations) {
        if (!a.executable) {
            continue;
        }
        if (a.type == MEM_IMAGE) {
            if (listed.contains(a.base)) {
                continue;
            }
            Finding f;
            f.kind = FindingKind::UnlistedImage;
            f.address = a.base;
            f.size = a.size;
            if (const auto file = process_.mappedFile(a.base)) {
                f.path = utf8(devicePathToDos(*file));
                f.module = fileName(f.path);
            }
            if (isWow64Layer(a.base, f.path)) {
                continue;
            }
            f.detail = "an executable image mapping that is not in the loader's module list";
            result_.findings.push_back(std::move(f));
            continue;
        }

        std::uint8_t header[0x400];
        if (!process_.read(a.base, header, sizeof(header)) || header[0] != 'M' || header[1] != 'Z') {
            continue;
        }
        std::uint32_t ntOffset = 0;
        std::memcpy(&ntOffset, header + 0x3C, 4);
        if (ntOffset > sizeof(header) - 4 || std::memcmp(header + ntOffset, "PE\0\0", 4) != 0) {
            continue;
        }
        Finding f;
        f.kind = FindingKind::PrivateImage;
        f.address = a.base;
        f.size = a.size;
        f.detail = std::string("a PE header at the start of ") + (a.type == MEM_MAPPED ? "mapped" : "private") +
                   " executable memory, which is not a loaded module";
        result_.findings.push_back(std::move(f));
    }
}

std::optional<ScanResult> Scan::run(std::string* error) {
    std::string listError;
    std::vector<ModuleInfo> infos = process_.modules(&listError);
    if (infos.empty()) {
        if (error) {
            *error = listError.empty() ? "the process has no modules" : listError;
        }
        return std::nullopt;
    }

    result_.pid = process_.pid();
    result_.processName = process_.name();
    result_.bitness = Process::bitness();
    result_.modulesListed = infos.size();

    for (ModuleInfo& info : infos) {
        ModuleState m;
        m.lowerName = toLower(info.name);
        m.info = std::move(info);
        modules_.push_back(std::move(m));
    }
    for (std::size_t i = 0; i < modules_.size(); ++i) {
        byBase_.push_back(i);
        byName_[modules_[i].lowerName].push_back(i);
    }
    std::sort(byBase_.begin(), byBase_.end(), [this](std::size_t a, std::size_t b) { return modules_[a].info.base < modules_[b].info.base; });

    std::set<std::string> wanted;
    for (const std::string& name : options_.modules) {
        wanted.insert(toLower(name));
    }
    std::set<std::string> seen;

    for (std::size_t i = 0; i < modules_.size(); ++i) {
        if (!wanted.empty() && !wanted.contains(modules_[i].lowerName)) {
            continue;
        }
        seen.insert(modules_[i].lowerName);
        ++result_.modulesScanned;
        ModuleState& m = load(i);

        if (m.unbacked || m.fileMissing) {
            Finding f;
            f.kind = FindingKind::UnbackedModule;
            f.module = m.info.name;
            f.moduleBase = m.info.base;
            f.address = m.info.base;
            f.size = m.info.size;
            f.path = m.path.empty() ? m.info.path : m.path;
            f.detail = m.unbacked ? m.problem : "the file behind the module can no longer be opened (" + m.problem + ")";
            result_.findings.push_back(std::move(f));
            continue;
        }
        if (!m.reference) {
            note(m.info.name + ": " + m.problem + "; not compared");
            continue;
        }
        if (!checkHeaders(m)) {
            continue;
        }
        checkCode(m);
        checkImports(m);
        checkExports(m);
    }

    for (const std::string& name : wanted) {
        if (!seen.contains(name)) {
            note("no loaded module is named " + name);
        }
    }
    if (wanted.empty()) {
        checkMemory();
    }
    return std::move(result_);
}

} // namespace

const char* kindName(FindingKind kind) {
    switch (kind) {
    case FindingKind::InlinePatch:
        return "inline";
    case FindingKind::IatHook:
        return "iat";
    case FindingKind::EatHook:
        return "eat";
    case FindingKind::UnbackedModule:
        return "unbacked-module";
    case FindingKind::ImageMismatch:
        return "image-mismatch";
    case FindingKind::UnlistedImage:
        return "unlisted-image";
    case FindingKind::PrivateImage:
        return "private-image";
    }
    return "unknown";
}

std::string AddressInfo::text() const {
    if (!module.empty()) {
        return symbol.empty() ? module + "+" + hex(offset) : module + "!" + symbol;
    }
    std::string out = memory + " " + hex(address);
    if (!file.empty()) {
        out += " (" + file + ")";
    }
    return out;
}

std::optional<ScanResult> scan(const Process& process, const ScanOptions& options, std::string* error) {
    Scan s(process, options);
    return s.run(error);
}

std::optional<ScanResult> scanProcess(std::uint32_t pid, const ScanOptions& options, std::string* error) {
    const auto process = Process::open(pid, error);
    if (!process) {
        return std::nullopt;
    }
    return scan(*process, options, error);
}

std::optional<ScanResult> scanCurrentProcess(const ScanOptions& options, std::string* error) {
    const auto process = Process::current();
    return scan(*process, options, error);
}

} // namespace hookscan
