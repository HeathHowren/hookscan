#pragma once

// Starts a child with its stdin and stdout on pipes. Used to run the fixture
// (which prints a ready line and waits for stdin to close) and the CLI.

#include <windows.h>

#include <chrono>
#include <cstdint>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

namespace test {

class ChildProcess {
public:
    explicit ChildProcess(const std::wstring& commandLine) {
        SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
        HANDLE childIn = nullptr;
        HANDLE childOut = nullptr;
        if (!CreatePipe(&childIn, &stdinWrite_, &inherit, 0) || !CreatePipe(&stdoutRead_, &childOut, &inherit, 0)) {
            throw std::runtime_error("CreatePipe failed");
        }
        SetHandleInformation(stdinWrite_, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(stdoutRead_, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = childIn;
        si.hStdOutput = childOut;
        si.hStdError = childOut;
        std::wstring mutableLine = commandLine;
        const BOOL ok = CreateProcessW(nullptr, mutableLine.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi_);
        CloseHandle(childIn);
        CloseHandle(childOut);
        if (!ok) {
            throw std::runtime_error("CreateProcess failed: " + std::to_string(GetLastError()));
        }
    }

    ~ChildProcess() {
        closeInput();
        if (WaitForSingleObject(pi_.hProcess, 5000) != WAIT_OBJECT_0) {
            TerminateProcess(pi_.hProcess, 1);
            WaitForSingleObject(pi_.hProcess, 5000);
        }
        CloseHandle(stdoutRead_);
        CloseHandle(pi_.hThread);
        CloseHandle(pi_.hProcess);
    }

    ChildProcess(const ChildProcess&) = delete;
    ChildProcess& operator=(const ChildProcess&) = delete;

    [[nodiscard]] std::uint32_t pid() const { return pi_.dwProcessId; }

    void closeInput() {
        if (stdinWrite_) {
            CloseHandle(stdinWrite_);
            stdinWrite_ = nullptr;
        }
    }

    // Reads one line from the child's stdout, waiting up to `timeout`.
    [[nodiscard]] std::string readLine(std::chrono::milliseconds timeout = std::chrono::seconds(30)) {
        std::string line;
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            DWORD available = 0;
            if (!PeekNamedPipe(stdoutRead_, nullptr, 0, nullptr, &available, nullptr)) {
                break; // the child exited and closed the pipe
            }
            if (available == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            char c = 0;
            DWORD got = 0;
            if (!ReadFile(stdoutRead_, &c, 1, &got, nullptr) || got == 0) {
                break;
            }
            if (c == '\n') {
                return line;
            }
            if (c != '\r') {
                line += c;
            }
        }
        return line;
    }

    // Reads everything until the child exits, then returns its exit code.
    [[nodiscard]] DWORD readAllAndWait(std::string& output) {
        closeInput();
        char buffer[4096];
        DWORD got = 0;
        while (ReadFile(stdoutRead_, buffer, sizeof(buffer), &got, nullptr) && got != 0) {
            output.append(buffer, got);
        }
        WaitForSingleObject(pi_.hProcess, 60000);
        DWORD code = 0;
        GetExitCodeProcess(pi_.hProcess, &code);
        return code;
    }

private:
    PROCESS_INFORMATION pi_{};
    HANDLE stdinWrite_ = nullptr;
    HANDLE stdoutRead_ = nullptr;
};

inline std::wstring widen(const std::string& text) {
    return std::wstring(text.begin(), text.end());
}

// The fixture, started in one mode, with its ready line parsed.
class Fixture {
public:
    explicit Fixture(const std::string& mode) : child_(L"\"" + widen(HOOKSCAN_FIXTURE_EXE) + L"\" " + widen(mode)) {
        ready_ = child_.readLine();
        std::istringstream words(ready_);
        std::string word;
        while (words >> word) {
            const auto eq = word.find('=');
            if (eq != std::string::npos) {
                values_[word.substr(0, eq)] = word.substr(eq + 1);
            }
        }
    }

    [[nodiscard]] std::uint32_t pid() const { return child_.pid(); }
    [[nodiscard]] const std::string& readyLine() const { return ready_; }
    [[nodiscard]] bool ready() const { return ready_.starts_with("ready"); }
    [[nodiscard]] std::string text(const std::string& key) const {
        const auto it = values_.find(key);
        return it == values_.end() ? std::string() : it->second;
    }
    [[nodiscard]] std::uint64_t value(const std::string& key) const { return std::stoull(text(key), nullptr, 0); }

private:
    ChildProcess child_;
    std::string ready_;
    std::map<std::string, std::string> values_;
};

} // namespace test
