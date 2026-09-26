#pragma once

#include "core/Diff.h"
#include "core/Disasm.h"
#include "core/MemoryReader.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace hookscan {

struct ModuleInfo {
    std::string name; // base name as the loader lists it
    std::string path; // the loader's full path
    std::uint64_t base = 0;
    std::uint32_t size = 0;
};

struct MemoryRegion {
    std::uint64_t base = 0;
    std::uint64_t allocationBase = 0;
    std::uint64_t size = 0;
    std::uint32_t state = 0;   // MEM_COMMIT, MEM_RESERVE, MEM_FREE
    std::uint32_t protect = 0; // PAGE_*
    std::uint32_t type = 0;    // MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE

    [[nodiscard]] bool executable() const;
    [[nodiscard]] bool isImage() const;
    [[nodiscard]] bool isPrivate() const;
    [[nodiscard]] bool isMapped() const;
    [[nodiscard]] bool isFree() const;
};

// A process opened for reading only: PROCESS_QUERY_INFORMATION |
// PROCESS_VM_READ. Nothing in hookscan asks for write, operation or thread
// access, so nothing in it can change the target.
class Process final : public MemoryReader {
public:
    // Fails when the process cannot be opened or its bitness differs from
    // this build's (a 64-bit hookscan reads 64-bit processes, the 32-bit one
    // reads 32-bit processes).
    [[nodiscard]] static std::unique_ptr<Process> open(std::uint32_t pid, std::string* error);
    [[nodiscard]] static std::unique_ptr<Process> current();

    ~Process() override;
    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;

    bool read(std::uint64_t address, void* out, std::size_t size) const override;

    // Reads a range page by page where a large read fails. Unreadable pages
    // are left zero and reported in `unreadable`, as offsets into the result.
    [[nodiscard]] std::vector<std::uint8_t> readRange(std::uint64_t address, std::size_t size, std::vector<ByteRange>& unreadable) const;

    [[nodiscard]] std::uint32_t pid() const { return pid_; }
    [[nodiscard]] const std::string& name() const { return name_; }
    [[nodiscard]] static Bitness bitness();

    [[nodiscard]] std::vector<ModuleInfo> modules(std::string* error) const;
    [[nodiscard]] std::vector<MemoryRegion> regions() const;
    [[nodiscard]] std::optional<MemoryRegion> query(std::uint64_t address) const;

    // The file behind an image or file-mapped view at `address`, as an NT
    // device path ("\Device\HarddiskVolume3\Windows\System32\ntdll.dll"), or
    // nothing when the memory is not backed by a file.
    [[nodiscard]] std::optional<std::wstring> mappedFile(std::uint64_t address) const;

private:
    Process() = default;

    void* handle_ = nullptr;
    bool ownsHandle_ = false;
    std::uint32_t pid_ = 0;
    std::string name_;
};

// Opens an NT device path through \\?\GLOBALROOT and reads the whole file.
// Returns nothing and sets `errorCode` (a Win32 error) on failure.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> readDeviceFile(const std::wstring& devicePath, unsigned long* errorCode);

// "\Device\HarddiskVolume3\Windows\x.dll" -> "C:\Windows\x.dll" when a drive
// letter maps to that device; the device path unchanged otherwise.
[[nodiscard]] std::wstring devicePathToDos(const std::wstring& devicePath);

// FormatMessage text for a Win32 error code, without the trailing period.
[[nodiscard]] std::string win32ErrorText(unsigned long code);

[[nodiscard]] std::string utf8(const std::wstring& text);
[[nodiscard]] std::wstring widen(const std::string& text);

} // namespace hookscan
