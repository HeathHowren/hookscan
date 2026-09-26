#include "core/Report.h"

#include <catch2/catch_test_macros.hpp>

using namespace hookscan;

namespace {

ScanResult sampleResult() {
    ScanResult r;
    r.pid = 1234;
    r.processName = "game.exe";
    r.bitness = Bitness::X64;
    r.modulesListed = 5;
    r.modulesScanned = 5;

    Finding iat;
    iat.kind = FindingKind::IatHook;
    iat.module = "game.exe";
    iat.moduleBase = 0x140000000;
    iat.address = 0x140020010;
    iat.size = 8;
    iat.importedModule = "KERNEL32.dll";
    iat.function = "GetTickCount";
    AddressInfo expected;
    expected.address = 0x7FF800001000;
    expected.module = "KERNEL32.DLL";
    expected.offset = 0x1000;
    expected.symbol = "GetTickCount";
    iat.expected = expected;
    AddressInfo target;
    target.address = 0x2A0000;
    target.memory = "private memory";
    iat.target = target;
    r.findings.push_back(iat);

    Finding unlisted;
    unlisted.kind = FindingKind::UnlistedImage;
    unlisted.module = "tool.dll";
    unlisted.address = 0x180000000;
    unlisted.size = 0x21000;
    unlisted.path = "C:\\tools\\tool.dll";
    unlisted.detail = "an executable image mapping that is not in the loader's module list";
    r.findings.push_back(unlisted);

    r.notes.push_back("ntdll.dll: something \"quoted\"");
    return r;
}

} // namespace

TEST_CASE("addresses describe themselves by module and export, or by memory kind", "[report]") {
    AddressInfo a;
    a.address = 0x7FF800001000;
    a.module = "kernel32.dll";
    a.offset = 0x1000;
    CHECK(a.text() == "kernel32.dll+0x1000");
    a.symbol = "Sleep";
    CHECK(a.text() == "kernel32.dll!Sleep");

    AddressInfo b;
    b.address = 0x2A0000;
    b.memory = "unlisted image";
    b.file = "C:\\x.dll";
    CHECK(b.text() == "unlisted image 0x2A0000 (C:\\x.dll)");
}

TEST_CASE("the text report shows each finding and the count", "[report]") {
    const std::string text = formatText(sampleResult(), false);
    CHECK(text.starts_with("hookscan " HOOKSCAN_VERSION ": pid 1234 (game.exe, x64), 5 of 5 modules scanned\n"));
    CHECK(text.find("[iat] game.exe imports KERNEL32.dll!GetTickCount\n") != std::string::npos);
    CHECK(text.find("  slot      game.exe+0x20010\n") != std::string::npos);
    CHECK(text.find("  expected  KERNEL32.DLL!GetTickCount\n") != std::string::npos);
    CHECK(text.find("  target    private memory 0x2A0000\n") != std::string::npos);
    CHECK(text.find("[unlisted-image] tool.dll at 0x180000000, 0x21000 bytes\n") != std::string::npos);
    CHECK(text.find("  file      C:\\tools\\tool.dll\n") != std::string::npos);
    CHECK(text.ends_with("2 findings, 1 note (--notes shows them)\n"));
    CHECK(text.find("note: ntdll.dll") == std::string::npos);

    const std::string withNotes = formatText(sampleResult(), true);
    CHECK(withNotes.find("note: ntdll.dll: something \"quoted\"\n") != std::string::npos);
    CHECK(withNotes.ends_with("2 findings\n"));
}

TEST_CASE("an empty result says no findings", "[report]") {
    ScanResult r;
    r.processName = "x.exe";
    CHECK(formatText(r, true).ends_with("\nno findings\n"));
    const std::string json = formatJson(r);
    CHECK(json.find("\"findings\": [],") != std::string::npos);
    CHECK(json.find("\"notes\": []") != std::string::npos);
}

TEST_CASE("JSON output escapes strings and writes addresses as hex strings", "[report]") {
    const std::string json = formatJson(sampleResult());
    CHECK(json.find("\"pid\": 1234") != std::string::npos);
    CHECK(json.find("\"kind\": \"iat\", \"module\": \"game.exe\", \"moduleBase\": \"0x140000000\", \"rva\": \"0x20010\"") != std::string::npos);
    CHECK(json.find("\"expected\": {\"address\": \"0x7FF800001000\", \"text\": \"KERNEL32.DLL!GetTickCount\", \"module\": \"KERNEL32.DLL\", "
                    "\"offset\": \"0x1000\", \"symbol\": \"GetTickCount\"}") != std::string::npos);
    CHECK(json.find("\"memory\": \"private memory\"") != std::string::npos);
    CHECK(json.find("\"file\": \"C:\\\\tools\\\\tool.dll\"") != std::string::npos);
    CHECK(json.find("\"ntdll.dll: something \\\"quoted\\\"\"") != std::string::npos);
}

TEST_CASE("jsonEscape handles quotes, backslashes and control characters", "[report]") {
    CHECK(jsonEscape("a\"b") == "a\\\"b");
    CHECK(jsonEscape("c:\\x") == "c:\\\\x");
    CHECK(jsonEscape("line\nnext\ttab") == "line\\nnext\\ttab");
    CHECK(jsonEscape(std::string("\x01", 1)) == "\\u0001");
    CHECK(jsonEscape("plain") == "plain");
}
