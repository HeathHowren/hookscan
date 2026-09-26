#include "core/Process.h"

#include <windows.h>
#include <psapi.h>

#include <algorithm>
#include <cstring>
#include <mutex>
#include <utility>

namespace hookscan {

namespace {

constexpr std::size_t kPage = 0x1000;
constexpr std::size_t kChunk = 0x10000;

} // namespace

std::string win32ErrorText(unsigned long code) {
    wchar_t* buffer = nullptr;
    const DWORD length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code,
                                        0, reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
    std::wstring text = length && buffer ? std::wstring(buffer, length) : std::wstring(L"error ") + std::to_wstring(code);
    if (buffer) {
        LocalFree(buffer);
    }
    while (!text.empty() && (text.back() == L'\n' || text.back() == L'\r' || text.back() == L'.')) {
        text.pop_back();
    }
    return utf8(text);
}

namespace {

std::string baseName(const std::wstring& path) {
    const auto slash = path.find_last_of(L"\\/");
    return utf8(slash == std::wstring::npos ? path : path.substr(slash + 1));
}

} // namespace

std::string utf8(const std::wstring& text) {
    if (text.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size, nullptr, nullptr);
    return out;
}

std::wstring widen(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring out(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size);
    return out;
}

bool MemoryRegion::executable() const {
    constexpr std::uint32_t kExec = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return state == MEM_COMMIT && (protect & kExec) != 0 && (protect & PAGE_GUARD) == 0;
}

bool MemoryRegion::isImage() const {
    return type == MEM_IMAGE;
}

bool MemoryRegion::isPrivate() const {
    return type == MEM_PRIVATE;
}

bool MemoryRegion::isMapped() const {
    return type == MEM_MAPPED;
}

bool MemoryRegion::isFree() const {
    return state == MEM_FREE;
}

std::unique_ptr<Process> Process::open(std::uint32_t pid, std::string* error) {
    HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!handle) {
        const DWORD code = GetLastError();
        if (error) {
            *error = "cannot open process " + std::to_string(pid) + ": " + win32ErrorText(code);
            if (code == ERROR_ACCESS_DENIED) {
                *error += " (a process owned by another user or running elevated needs hookscan to run elevated too)";
            }
        }
        return nullptr;
    }

    BOOL selfWow64 = FALSE;
    BOOL targetWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &selfWow64);
    if (!IsWow64Process(handle, &targetWow64)) {
        targetWow64 = selfWow64;
    }
    if (selfWow64 != targetWow64) {
        CloseHandle(handle);
        if (error) {
#if defined(_WIN64)
            *error = "process " + std::to_string(pid) + " is 32-bit; use the x86 build of hookscan for it";
#else
            *error = "process " + std::to_string(pid) + " is 64-bit; use the x64 build of hookscan for it";
#endif
        }
        return nullptr;
    }

    std::unique_ptr<Process> process(new Process());
    process->handle_ = handle;
    process->ownsHandle_ = true;
    process->pid_ = pid;
    wchar_t path[MAX_PATH * 4];
    DWORD length = static_cast<DWORD>(std::size(path));
    if (QueryFullProcessImageNameW(handle, 0, path, &length)) {
        process->name_ = baseName(std::wstring(path, length));
    }
    return process;
}

std::unique_ptr<Process> Process::current() {
    std::unique_ptr<Process> process(new Process());
    process->handle_ = GetCurrentProcess();
    process->ownsHandle_ = false;
    process->pid_ = GetCurrentProcessId();
    wchar_t path[MAX_PATH * 4];
    const DWORD length = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
    process->name_ = baseName(std::wstring(path, length));
    return process;
}

Process::~Process() {
    if (ownsHandle_ && handle_) {
        CloseHandle(handle_);
    }
}

Bitness Process::bitness() {
#if defined(_WIN64)
    return Bitness::X64;
#else
    return Bitness::X86;
#endif
}

bool Process::read(std::uint64_t address, void* out, std::size_t size) const {
    if (size == 0) {
        return true;
    }
#if !defined(_WIN64)
    if (address > 0xFFFFFFFFull || 0xFFFFFFFFull - address < size - 1) {
        return false;
    }
#endif
    SIZE_T got = 0;
    return ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)), out, size, &got) && got == size;
}

std::vector<std::uint8_t> Process::readRange(std::uint64_t address, std::size_t size, std::vector<ByteRange>& unreadable) const {
    std::vector<std::uint8_t> out(size, 0);
    std::size_t done = 0;
    auto markUnreadable = [&](std::size_t from, std::size_t to) {
        const auto begin = static_cast<std::uint32_t>(from);
        const auto end = static_cast<std::uint32_t>(to);
        if (!unreadable.empty() && unreadable.back().end == begin) {
            unreadable.back().end = end;
        } else {
            unreadable.push_back({begin, end});
        }
    };
    while (done < size) {
        const std::size_t chunk = std::min(kChunk, size - done);
        if (read(address + done, out.data() + done, chunk)) {
            done += chunk;
            continue;
        }
        // Page by page, so one unreadable page costs one page.
        const std::size_t chunkEnd = done + chunk;
        while (done < chunkEnd) {
            const std::uint64_t at = address + done;
            const std::size_t toPageEnd = kPage - static_cast<std::size_t>(at % kPage);
            const std::size_t step = std::min(toPageEnd, chunkEnd - done);
            if (!read(at, out.data() + done, step)) {
                std::memset(out.data() + done, 0, step);
                markUnreadable(done, done + step);
            }
            done += step;
        }
    }
    return out;
}

std::vector<ModuleInfo> Process::modules(std::string* error) const {
    std::vector<HMODULE> handles(512);
    DWORD needed = 0;
    // The list can change between the size query and the copy, and a process
    // that is still starting returns ERROR_PARTIAL_COPY; retry a few times.
    bool ok = false;
    for (int attempt = 0; attempt < 5; ++attempt) {
        if (EnumProcessModulesEx(handle_, handles.data(), static_cast<DWORD>(handles.size() * sizeof(HMODULE)), &needed, LIST_MODULES_DEFAULT)) {
            if (needed <= handles.size() * sizeof(HMODULE)) {
                handles.resize(needed / sizeof(HMODULE));
                ok = true;
                break;
            }
            handles.resize(needed / sizeof(HMODULE) + 64);
            continue;
        }
        Sleep(20);
    }
    if (!ok) {
        if (error) {
            *error = "cannot list the modules of process " + std::to_string(pid_) + ": " + win32ErrorText(GetLastError());
        }
        return {};
    }

    std::vector<ModuleInfo> out;
    for (HMODULE module : handles) {
        MODULEINFO info{};
        if (!GetModuleInformation(handle_, module, &info, sizeof(info))) {
            continue; // unloaded since the list was taken
        }
        ModuleInfo m;
        m.base = reinterpret_cast<std::uintptr_t>(info.lpBaseOfDll);
        m.size = info.SizeOfImage;
        wchar_t text[MAX_PATH * 4];
        DWORD length = GetModuleBaseNameW(handle_, module, text, static_cast<DWORD>(std::size(text)));
        m.name = utf8(std::wstring(text, length));
        length = GetModuleFileNameExW(handle_, module, text, static_cast<DWORD>(std::size(text)));
        m.path = utf8(std::wstring(text, length));
        out.push_back(std::move(m));
    }
    return out;
}

std::optional<MemoryRegion> Process::query(std::uint64_t address) const {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(handle_, reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)), &mbi, sizeof(mbi)) != sizeof(mbi)) {
        return std::nullopt;
    }
    MemoryRegion r;
    r.base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
    r.allocationBase = reinterpret_cast<std::uintptr_t>(mbi.AllocationBase);
    r.size = mbi.RegionSize;
    r.state = mbi.State;
    r.protect = mbi.Protect;
    r.type = mbi.Type;
    return r;
}

std::vector<MemoryRegion> Process::regions() const {
    std::vector<MemoryRegion> out;
    std::uint64_t address = 0;
    while (const auto r = query(address)) {
        if (r->size == 0 || r->base + r->size <= address) {
            break;
        }
        out.push_back(*r);
        address = r->base + r->size;
    }
    return out;
}

std::optional<std::wstring> Process::mappedFile(std::uint64_t address) const {
    wchar_t text[MAX_PATH * 4];
    const DWORD length =
        GetMappedFileNameW(handle_, reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(address)), text, static_cast<DWORD>(std::size(text)));
    if (length == 0) {
        return std::nullopt;
    }
    return std::wstring(text, length);
}

std::optional<std::vector<std::uint8_t>> readDeviceFile(const std::wstring& devicePath, unsigned long* errorCode) {
    const std::wstring path = L"\\\\?\\GLOBALROOT" + devicePath;
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (errorCode) {
            *errorCode = GetLastError();
        }
        return std::nullopt;
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart > 0x40000000) {
        if (errorCode) {
            *errorCode = size.QuadPart > 0x40000000 ? ERROR_FILE_TOO_LARGE : GetLastError();
        }
        CloseHandle(file);
        return std::nullopt;
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));
    std::size_t done = 0;
    while (done < bytes.size()) {
        DWORD got = 0;
        const DWORD want = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - done, 0x1000000));
        if (!ReadFile(file, bytes.data() + done, want, &got, nullptr) || got == 0) {
            if (errorCode) {
                *errorCode = GetLastError();
            }
            CloseHandle(file);
            return std::nullopt;
        }
        done += got;
    }
    CloseHandle(file);
    return bytes;
}

std::wstring devicePathToDos(const std::wstring& devicePath) {
    static std::once_flag once;
    static std::vector<std::pair<std::wstring, std::wstring>> drives; // device -> "C:"
    std::call_once(once, [] {
        wchar_t letters[512];
        const DWORD length = GetLogicalDriveStringsW(static_cast<DWORD>(std::size(letters)), letters);
        for (const wchar_t* p = letters; length && *p; p += wcslen(p) + 1) {
            const std::wstring drive(p, 2); // "C:"
            wchar_t target[MAX_PATH];
            if (QueryDosDeviceW(drive.c_str(), target, static_cast<DWORD>(std::size(target)))) {
                drives.emplace_back(target, drive);
            }
        }
    });
    for (const auto& [device, drive] : drives) {
        if (devicePath.size() > device.size() && devicePath[device.size()] == L'\\' &&
            _wcsnicmp(devicePath.c_str(), device.c_str(), device.size()) == 0) {
            return drive + devicePath.substr(device.size());
        }
    }
    const std::wstring mup = L"\\Device\\Mup\\";
    if (devicePath.size() > mup.size() && _wcsnicmp(devicePath.c_str(), mup.c_str(), mup.size()) == 0) {
        return L"\\\\" + devicePath.substr(mup.size());
    }
    return devicePath;
}

} // namespace hookscan
