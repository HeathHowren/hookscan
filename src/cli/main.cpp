// hookscan: reports code, import and export entries in a running process that
// differ from the modules' files on disk. Read-only: the target is opened with
// PROCESS_QUERY_INFORMATION | PROCESS_VM_READ and nothing else.

#include "core/Process.h"
#include "core/Report.h"
#include "core/Scanner.h"

#include <windows.h>
#include <tlhelp32.h>

#include <cstdio>
#include <fcntl.h>
#include <io.h>
#include <cstdlib>
#include <optional>
#include <string>
#include <vector>

namespace {

constexpr int kExitClean = 0;
constexpr int kExitFindings = 1;
constexpr int kExitError = 2;

const char* kUsage =
    "usage: hookscan (--pid <pid> | --name <process.exe> | --self) [options]\n"
    "\n"
    "Reports code in a running process that differs from the module files on\n"
    "disk (inline patches), import and export table entries that point where\n"
    "the files say they should not, and modules with no file or a file that\n"
    "does not match. Opens the target read-only.\n"
    "\n"
    "target:\n"
    "  --pid <pid>          the process to scan\n"
    "  --name <exe>         the process with this image name (must be unique)\n"
    "  --self               scan hookscan's own process\n"
    "\n"
    "options:\n"
    "  --json               print one JSON object instead of the report\n"
    "  --module <name>      scan only this module; repeatable. Skips the\n"
    "                       process-wide checks for unlisted images\n"
    "  --notes              list what could not be checked, and why\n"
    "  --include-writable   also compare executable sections that are writable\n"
    "  --gap <n>            equal bytes allowed inside one patch region (default 8)\n"
    "  --version            print the version\n"
    "  --help               print this text\n"
    "\n"
    "exit status: 0 no findings, 1 findings, 2 error\n";

void print(const std::string& text, FILE* stream = stdout) {
    std::fwrite(text.data(), 1, text.size(), stream);
}

int fail(const std::string& message) {
    print("hookscan: " + message + "\n", stderr);
    return kExitError;
}

bool parseNumber(const char* text, unsigned long& out) {
    char* end = nullptr;
    out = std::strtoul(text, &end, 0);
    return end != text && *end == '\0';
}

// The PIDs of every process whose image name is `name`.
std::vector<std::uint32_t> findByName(const std::wstring& name) {
    std::vector<std::uint32_t> out;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return out;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    for (BOOL more = Process32FirstW(snapshot, &entry); more; more = Process32NextW(snapshot, &entry)) {
        if (_wcsicmp(entry.szExeFile, name.c_str()) == 0) {
            out.push_back(entry.th32ProcessID);
        }
    }
    CloseHandle(snapshot);
    return out;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    // Plain LF output, so JSON piped to another tool is byte-for-byte what was written.
    _setmode(_fileno(stdout), _O_BINARY);
    _setmode(_fileno(stderr), _O_BINARY);
    hookscan::ScanOptions options;
    bool json = false;
    bool notes = false;
    bool self = false;
    std::optional<std::uint32_t> pid;
    std::wstring name;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = hookscan::utf8(argv[i]);
        auto value = [&]() -> const wchar_t* { return i + 1 < argc ? argv[++i] : nullptr; };
        if (arg == "--help" || arg == "-h" || arg == "/?") {
            print(kUsage);
            return kExitClean;
        }
        if (arg == "--version") {
            print("hookscan " HOOKSCAN_VERSION "\n");
            return kExitClean;
        }
        if (arg == "--json") {
            json = true;
        } else if (arg == "--notes") {
            notes = true;
        } else if (arg == "--self") {
            self = true;
        } else if (arg == "--include-writable") {
            options.includeWritable = true;
        } else if (arg == "--pid") {
            const wchar_t* v = value();
            unsigned long n = 0;
            if (!v || !parseNumber(hookscan::utf8(v).c_str(), n)) {
                return fail("--pid needs a process ID");
            }
            pid = static_cast<std::uint32_t>(n);
        } else if (arg == "--name") {
            const wchar_t* v = value();
            if (!v || !*v) {
                return fail("--name needs an image name, such as game.exe");
            }
            name = v;
        } else if (arg == "--module") {
            const wchar_t* v = value();
            if (!v || !*v) {
                return fail("--module needs a module name, such as kernel32.dll");
            }
            options.modules.push_back(hookscan::utf8(v));
        } else if (arg == "--gap") {
            const wchar_t* v = value();
            unsigned long n = 0;
            if (!v || !parseNumber(hookscan::utf8(v).c_str(), n) || n > 64) {
                return fail("--gap needs a number from 0 to 64");
            }
            options.mergeGap = static_cast<std::uint32_t>(n);
        } else {
            return fail("unknown argument '" + arg + "'; see --help");
        }
    }

    const int targets = (pid ? 1 : 0) + (name.empty() ? 0 : 1) + (self ? 1 : 0);
    if (targets != 1) {
        print(kUsage, stderr);
        return kExitError;
    }

    if (!name.empty()) {
        const auto pids = findByName(name);
        if (pids.empty()) {
            return fail("no running process is named " + hookscan::utf8(name));
        }
        if (pids.size() > 1) {
            std::string list;
            for (const auto p : pids) {
                list += (list.empty() ? "" : ", ") + std::to_string(p);
            }
            return fail(std::to_string(pids.size()) + " processes are named " + hookscan::utf8(name) + " (" + list + "); pick one with --pid");
        }
        pid = pids.front();
    }

    std::string error;
    const auto result = self ? hookscan::scanCurrentProcess(options, &error) : hookscan::scanProcess(*pid, options, &error);
    if (!result) {
        return fail(error);
    }
    print(json ? hookscan::formatJson(*result) : hookscan::formatText(*result, notes));
    return result->findings.empty() ? kExitClean : kExitFindings;
}
