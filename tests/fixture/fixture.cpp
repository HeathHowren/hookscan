// The test fixture. It changes its own process, and only its own process, in
// one known way per mode, prints what it changed, and waits for stdin to close.
//
//   clean     changes nothing
//   hooked    a 5-byte jmp over FixtureTarget, to FixtureDetour, and its
//             GetTickCount import slot pointed at FixtureFakeTickCount
//   eat       the export FixtureExported pointed at a stub outside the image
//   int3      0xCC over the first byte of FixtureBreakpointTarget
//   unlisted  a second mapping of its own exe, as an image, that the loader
//             never registered
//   private   a copy of its own headers in private executable memory
//
// The ready line is "ready mode=<mode> base=0x... key=0x..." with the RVAs or
// addresses the tests assert on.

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

extern "C" {

__declspec(dllexport) __declspec(noinline) int FixtureTarget(int x) {
    volatile int y = x * 3;
    return y + 7;
}

__declspec(dllexport) __declspec(noinline) int FixtureDetour(int x) {
    volatile int y = x;
    return y + 1000;
}

// GetTickCount takes no arguments, so __cdecl and __stdcall agree on the
// calling convention here, and the x86 export name stays undecorated.
__declspec(dllexport) __declspec(noinline) DWORD FixtureFakeTickCount() {
    volatile DWORD value = 42;
    return value;
}

__declspec(dllexport) __declspec(noinline) int FixtureExported(int x) {
    volatile int y = x;
    return y - 1;
}

__declspec(dllexport) __declspec(noinline) int FixtureBreakpointTarget(int x) {
    volatile int y = x ^ 0x55;
    return y * 5;
}

} // extern "C"

namespace {

std::uintptr_t g_base = 0;

std::uintptr_t rva(const void* p) {
    return reinterpret_cast<std::uintptr_t>(p) - g_base;
}

void writeProtected(void* at, const void* bytes, std::size_t size, DWORD writable) {
    DWORD old = 0;
    VirtualProtect(at, size, writable, &old);
    std::memcpy(at, bytes, size);
    VirtualProtect(at, size, old, &old);
    FlushInstructionCache(GetCurrentProcess(), at, size);
}

IMAGE_NT_HEADERS* ntHeaders() {
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_base);
    return reinterpret_cast<IMAGE_NT_HEADERS*>(g_base + dos->e_lfanew);
}

void* slotForImport(const char* dll, const char* function) {
    const auto& dir = ntHeaders()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    for (auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(g_base + dir.VirtualAddress); desc->Name != 0; ++desc) {
        if (_stricmp(reinterpret_cast<const char*>(g_base + desc->Name), dll) != 0) {
            continue;
        }
        auto* names = reinterpret_cast<IMAGE_THUNK_DATA*>(g_base + desc->OriginalFirstThunk);
        auto* slots = reinterpret_cast<IMAGE_THUNK_DATA*>(g_base + desc->FirstThunk);
        for (; names->u1.AddressOfData != 0; ++names, ++slots) {
            if (IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal)) {
                continue;
            }
            const auto* byName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(g_base + names->u1.AddressOfData);
            if (std::strcmp(reinterpret_cast<const char*>(byName->Name), function) == 0) {
                return &slots->u1.Function;
            }
        }
    }
    return nullptr;
}

DWORD* slotForExport(const char* function) {
    const auto& dir = ntHeaders()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(g_base + dir.VirtualAddress);
    const auto* names = reinterpret_cast<const DWORD*>(g_base + exports->AddressOfNames);
    const auto* ordinals = reinterpret_cast<const WORD*>(g_base + exports->AddressOfNameOrdinals);
    auto* functions = reinterpret_cast<DWORD*>(g_base + exports->AddressOfFunctions);
    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        if (std::strcmp(reinterpret_cast<const char*>(g_base + names[i]), function) == 0) {
            return &functions[ordinals[i]];
        }
    }
    return nullptr;
}

std::string hex(std::uintptr_t value) {
    char text[32];
    std::snprintf(text, sizeof(text), "0x%llX", static_cast<unsigned long long>(value));
    return text;
}

// A 5-byte relative jmp over `from`.
std::string hookInline() {
    auto* from = reinterpret_cast<std::uint8_t*>(&FixtureTarget);
    auto* to = reinterpret_cast<std::uint8_t*>(&FixtureDetour);
    std::uint8_t jmp[5] = {0xE9};
    const auto rel = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(to) - (reinterpret_cast<std::intptr_t>(from) + 5));
    std::memcpy(jmp + 1, &rel, 4);
    writeProtected(from, jmp, sizeof(jmp), PAGE_EXECUTE_READWRITE);
    int (*volatile call)(int) = &FixtureTarget; // through a pointer, so the call is not folded
    const bool works = call(1) == 1001;
    return " inline=" + hex(rva(from)) + " detour=" + hex(rva(to)) + " inline_works=" + (works ? "1" : "0");
}

std::string hookImport() {
    void* slot = slotForImport("KERNEL32.dll", "GetTickCount");
    if (!slot) {
        return " iat=missing";
    }
    const void* fake = reinterpret_cast<const void*>(&FixtureFakeTickCount);
    writeProtected(slot, &fake, sizeof(fake), PAGE_READWRITE);
    const bool works = GetTickCount() == 42;
    return " iat=" + hex(rva(slot)) + " fake=" + hex(rva(fake)) + " iat_works=" + (works ? "1" : "0");
}

std::string hookExport() {
    DWORD* slot = slotForExport("FixtureExported");
    if (!slot) {
        return " eat=missing";
    }
    // An EAT entry is a 32-bit RVA, so the stub has to sit within 4 GiB above
    // the image. Try 64 KiB steps past its end.
    const std::uintptr_t imageEnd = g_base + ntHeaders()->OptionalHeader.SizeOfImage;
    std::uint8_t* stub = nullptr;
    for (std::uintptr_t at = (imageEnd + 0xFFFF) & ~std::uintptr_t{0xFFFF}; at - g_base < 0x7FFF0000 && !stub; at += 0x10000) {
        stub = static_cast<std::uint8_t*>(VirtualAlloc(reinterpret_cast<void*>(at), 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    }
    if (!stub) {
        return " eat=nostub";
    }
    const std::uint8_t code[] = {0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3}; // mov eax, 7; ret
    std::memcpy(stub, code, sizeof(code));
    DWORD old = 0;
    VirtualProtect(stub, 0x1000, PAGE_EXECUTE_READ, &old);
    const auto newRva = static_cast<DWORD>(reinterpret_cast<std::uintptr_t>(stub) - g_base);
    writeProtected(slot, &newRva, sizeof(newRva), PAGE_READWRITE);
    const bool works = reinterpret_cast<void*>(GetProcAddress(reinterpret_cast<HMODULE>(g_base), "FixtureExported")) == stub;
    return " eat=" + hex(rva(slot)) + " stub=" + hex(reinterpret_cast<std::uintptr_t>(stub)) + " eat_works=" + (works ? "1" : "0");
}

std::string breakpoint() {
    auto* at = reinterpret_cast<std::uint8_t*>(&FixtureBreakpointTarget);
    const std::uint8_t int3 = 0xCC;
    writeProtected(at, &int3, 1, PAGE_EXECUTE_READWRITE);
    return " int3=" + hex(rva(at));
}

std::string unlistedImage() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    HANDLE file = CreateFileW(path, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return " unlisted=nofile";
    }
    HANDLE section = CreateFileMappingW(file, nullptr, PAGE_EXECUTE_READ | SEC_IMAGE, 0, 0, nullptr);
    CloseHandle(file);
    if (!section) {
        return " unlisted=nosection";
    }
    void* view = MapViewOfFile(section, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, 0);
    CloseHandle(section);
    return " unlisted=" + hex(reinterpret_cast<std::uintptr_t>(view));
}

std::string privateImage() {
    void* copy = VirtualAlloc(nullptr, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    std::memcpy(copy, reinterpret_cast<const void*>(g_base), 0x1000);
    DWORD old = 0;
    VirtualProtect(copy, 0x2000, PAGE_EXECUTE_READ, &old);
    return " private=" + hex(reinterpret_cast<std::uintptr_t>(copy));
}

} // namespace

int main(int argc, char** argv) {
    g_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    const std::string mode = argc > 1 ? argv[1] : "clean";

    // Call everything once, so none of it is discarded and GetTickCount is
    // a real import.
    volatile int sink = FixtureTarget(1) + FixtureDetour(2) + FixtureExported(3) + FixtureBreakpointTarget(4) +
                        static_cast<int>(FixtureFakeTickCount()) + static_cast<int>(GetTickCount() & 1);
    (void)sink;

    std::string line = "ready mode=" + mode + " base=" + hex(g_base);
    if (mode == "hooked") {
        line += hookInline();
        line += hookImport();
    } else if (mode == "eat") {
        line += hookExport();
    } else if (mode == "int3") {
        line += breakpoint();
    } else if (mode == "unlisted") {
        line += unlistedImage();
    } else if (mode == "private") {
        line += privateImage();
    } else if (mode != "clean") {
        std::fprintf(stderr, "unknown mode %s\n", mode.c_str());
        return 2;
    }
    std::printf("%s\n", line.c_str());
    std::fflush(stdout);

    // Wait until the test closes our stdin.
    while (std::fgetc(stdin) != EOF) {
    }
    return 0;
}
