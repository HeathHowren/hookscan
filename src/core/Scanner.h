#pragma once

#include "core/Disasm.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace hookscan {

class Process;

enum class FindingKind {
    InlinePatch,    // code in an executable section differs from the relocated file
    IatHook,        // an import slot does not hold the address the export resolves to
    EatHook,        // an export slot differs from the file
    UnbackedModule, // a listed module with no file behind it, or whose file is gone
    ImageMismatch,  // a listed module whose headers do not match its file
    UnlistedImage,  // an executable image mapping the loader's module list does not name
    PrivateImage,   // a PE header at the start of private or mapped executable memory
};

[[nodiscard]] const char* kindName(FindingKind kind);

// An address, placed: inside a listed module (with an export name when it is
// exactly an export), or in some other kind of memory.
struct AddressInfo {
    std::uint64_t address = 0;
    std::string module;       // containing listed module, empty when none
    std::uint64_t offset = 0; // from the module base
    std::string symbol;       // export name when the address is exactly an export
    std::string memory;       // when not in a module: "private memory", "unlisted image", "mapped memory", "unallocated", "unknown"
    std::string file;         // for an unlisted image, the file behind it

    [[nodiscard]] bool inModule() const { return !module.empty(); }
    // "kernel32.dll!GetTickCount", "game.exe+0x1A20", "private memory 0x1F0000"
    [[nodiscard]] std::string text() const;
};

struct Finding {
    FindingKind kind = FindingKind::InlinePatch;
    std::string module;          // the module the finding is in; for unlisted memory, the file name if any
    std::uint64_t moduleBase = 0;
    std::uint64_t address = 0;   // first patched byte, the IAT or EAT slot, or the region base
    std::uint64_t size = 0;      // patch length or region size

    // InlinePatch
    std::string section;
    std::vector<std::uint8_t> original;
    std::vector<std::uint8_t> current;
    std::vector<Instruction> instructions;
    PatchShape shape = PatchShape::Other;

    // IatHook, EatHook
    std::string importedModule; // the DLL the import names
    std::string function;       // name, or "#ordinal"
    bool delayLoad = false;
    std::optional<AddressInfo> expected;

    // Where control or the pointer goes, when known.
    std::optional<AddressInfo> target;

    // The file path for module-level findings, and remarks.
    std::string path;
    std::string detail;
};

struct ScanOptions {
    // Scan only these modules (base names, compared case-insensitively). The
    // process-wide memory checks run only when this is empty.
    std::vector<std::string> modules;
    // Equal bytes allowed inside one patch region.
    std::uint32_t mergeGap = 8;
    // Compare executable sections that are also writable. Off by default:
    // such sections are meant to change (packers, JITs inside an image).
    bool includeWritable = false;
    // At most this many regions reported per section; the rest become a note.
    std::size_t maxRegionsPerSection = 64;
};

struct ScanResult {
    std::uint32_t pid = 0;
    std::string processName;
    Bitness bitness = Bitness::X64;
    std::size_t modulesListed = 0;
    std::size_t modulesScanned = 0;
    std::vector<Finding> findings;
    std::vector<std::string> notes;
};

// Scans an opened process. Returns nothing, with `error` set, only when the
// module list cannot be read at all; a module that cannot be checked becomes
// a note and the scan goes on.
[[nodiscard]] std::optional<ScanResult> scan(const Process& process, const ScanOptions& options, std::string* error);

// Opens `pid` read-only and scans it.
[[nodiscard]] std::optional<ScanResult> scanProcess(std::uint32_t pid, const ScanOptions& options, std::string* error);

// Scans the calling process: a program checking its own integrity.
[[nodiscard]] std::optional<ScanResult> scanCurrentProcess(const ScanOptions& options, std::string* error);

} // namespace hookscan
