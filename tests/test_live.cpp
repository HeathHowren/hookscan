// End-to-end: the fixture changes its own process in one known way, and the
// scanner, reading it from outside, must report exactly that and nothing else.

#include "ChildProcess.h"

#include "core/PeImage.h"
#include "core/Process.h"
#include "core/Scanner.h"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <filesystem>

using namespace hookscan;
using test::Fixture;

namespace {

const std::string kFixtureName = "hookscan_fixture.exe";

ScanResult scanFixture(const Fixture& fixture, const ScanOptions& options = {}) {
    REQUIRE(fixture.ready());
    std::string error;
    auto result = scanProcess(fixture.pid(), options, &error);
    INFO(error);
    REQUIRE(result);
    return std::move(*result);
}

std::string describe(const ScanResult& result) {
    std::string out;
    for (const Finding& f : result.findings) {
        out += std::string(kindName(f.kind)) + " " + f.module + " " + std::to_string(f.address - f.moduleBase) + " " + f.function + "\n";
    }
    return out;
}

} // namespace

TEST_CASE("an unmodified fixture has no findings", "[live]") {
    Fixture fixture("clean");
    const ScanResult result = scanFixture(fixture);
    INFO(describe(result));
    CHECK(result.findings.empty());
    CHECK(result.processName == kFixtureName);
    CHECK(result.modulesScanned == result.modulesListed);
    CHECK(result.modulesScanned >= 3); // the exe, ntdll, kernel32 at least
}

TEST_CASE("an inline jmp and an IAT redirection are reported exactly", "[live]") {
    Fixture fixture("hooked");
    REQUIRE(fixture.text("inline_works") == "1");
    REQUIRE(fixture.text("iat_works") == "1");
    const std::uint64_t base = fixture.value("base");

    const ScanResult result = scanFixture(fixture);
    INFO(describe(result));
    REQUIRE(result.findings.size() == 2);

    const auto inlineHook = std::find_if(result.findings.begin(), result.findings.end(), [](const Finding& f) { return f.kind == FindingKind::InlinePatch; });
    REQUIRE(inlineHook != result.findings.end());
    CHECK(inlineHook->module == kFixtureName);
    CHECK(inlineHook->moduleBase == base);
    CHECK(inlineHook->address == base + fixture.value("inline"));
    CHECK(inlineHook->size == 5);
    CHECK(inlineHook->section == ".text");
    REQUIRE(inlineHook->current.size() == 5);
    CHECK(inlineHook->current[0] == 0xE9);
    CHECK(inlineHook->original != inlineHook->current);
    CHECK(inlineHook->shape == PatchShape::JumpRelative);
    REQUIRE(inlineHook->instructions.size() == 1);
    CHECK(inlineHook->instructions[0].text.starts_with("jmp "));
    REQUIRE(inlineHook->target);
    CHECK(inlineHook->target->module == kFixtureName);
    CHECK(inlineHook->target->offset == fixture.value("detour"));
    CHECK(inlineHook->target->symbol == "FixtureDetour");
    CHECK(inlineHook->target->text() == kFixtureName + "!FixtureDetour");

    const auto iatHook = std::find_if(result.findings.begin(), result.findings.end(), [](const Finding& f) { return f.kind == FindingKind::IatHook; });
    REQUIRE(iatHook != result.findings.end());
    CHECK(iatHook->module == kFixtureName);
    CHECK(iatHook->address == base + fixture.value("iat"));
    CHECK(toLower(iatHook->importedModule) == "kernel32.dll");
    CHECK(iatHook->function == "GetTickCount");
    CHECK_FALSE(iatHook->delayLoad);
    REQUIRE(iatHook->target);
    CHECK(iatHook->target->module == kFixtureName);
    CHECK(iatHook->target->offset == fixture.value("fake"));
    CHECK(iatHook->target->symbol == "FixtureFakeTickCount");
    // What the slot should hold: GetTickCount, in kernel32 or wherever this
    // Windows version forwards it.
    REQUIRE(iatHook->expected);
    const std::string expectedModule = toLower(iatHook->expected->module);
    CHECK((expectedModule == "kernel32.dll" || expectedModule == "kernelbase.dll"));
    CHECK(iatHook->expected->symbol == "GetTickCount");
}

TEST_CASE("the module filter limits the scan to the named modules", "[live]") {
    Fixture fixture("hooked");

    ScanOptions onlyKernel32;
    onlyKernel32.modules = {"KERNEL32.DLL"};
    const ScanResult other = scanFixture(fixture, onlyKernel32);
    CHECK(other.findings.empty());
    CHECK(other.modulesScanned == 1);

    ScanOptions onlyFixture;
    onlyFixture.modules = {kFixtureName};
    const ScanResult own = scanFixture(fixture, onlyFixture);
    CHECK(own.findings.size() == 2);
    CHECK(own.modulesScanned == 1);

    ScanOptions missing;
    missing.modules = {"no-such-module.dll"};
    const ScanResult none = scanFixture(fixture, missing);
    CHECK(none.findings.empty());
    CHECK(none.modulesScanned == 0);
    REQUIRE(none.notes.size() == 1);
    CHECK(none.notes[0].find("no-such-module.dll") != std::string::npos);
}

TEST_CASE("an export pointed outside the module is reported", "[live]") {
    Fixture fixture("eat");
    REQUIRE(fixture.text("eat_works") == "1");
    const std::uint64_t base = fixture.value("base");

    const ScanResult result = scanFixture(fixture);
    INFO(describe(result));
    REQUIRE(result.findings.size() == 1);
    const Finding& f = result.findings[0];
    CHECK(f.kind == FindingKind::EatHook);
    CHECK(f.module == kFixtureName);
    CHECK(f.function == "FixtureExported");
    CHECK(f.address == base + fixture.value("eat"));
    REQUIRE(f.expected);
    CHECK(f.expected->symbol == "FixtureExported");
    REQUIRE(f.target);
    CHECK(f.target->address == fixture.value("stub"));
    CHECK_FALSE(f.target->inModule());
    CHECK(f.target->memory == "private memory");
    CHECK(f.detail.find("outside the module") != std::string::npos);
}

TEST_CASE("a software breakpoint byte is reported as int3", "[live]") {
    Fixture fixture("int3");
    const std::uint64_t base = fixture.value("base");

    const ScanResult result = scanFixture(fixture);
    INFO(describe(result));
    REQUIRE(result.findings.size() == 1);
    const Finding& f = result.findings[0];
    CHECK(f.kind == FindingKind::InlinePatch);
    CHECK(f.address == base + fixture.value("int3"));
    CHECK(f.size == 1);
    CHECK(f.shape == PatchShape::Breakpoint);
    CHECK(f.current == std::vector<std::uint8_t>{0xCC});
    CHECK_FALSE(f.target);
}

TEST_CASE("an image mapping the loader never registered is reported", "[live]") {
    Fixture fixture("unlisted");
    const ScanResult result = scanFixture(fixture);
    INFO(describe(result));
    REQUIRE(result.findings.size() == 1);
    const Finding& f = result.findings[0];
    CHECK(f.kind == FindingKind::UnlistedImage);
    CHECK(f.address == fixture.value("unlisted"));
    CHECK(f.module == kFixtureName);
    CHECK(std::filesystem::path(f.path).filename() == kFixtureName);
}

TEST_CASE("a PE header in private executable memory is reported", "[live]") {
    Fixture fixture("private");
    const ScanResult result = scanFixture(fixture);
    INFO(describe(result));
    REQUIRE(result.findings.size() == 1);
    CHECK(result.findings[0].kind == FindingKind::PrivateImage);
    CHECK(result.findings[0].address == fixture.value("private"));
}

TEST_CASE("the test process itself scans clean", "[live]") {
    std::string error;
    const auto result = scanCurrentProcess({}, &error);
    INFO(error);
    REQUIRE(result);
    INFO(describe(*result));
    CHECK(result->findings.empty());
    CHECK(result->pid == GetCurrentProcessId());
}

TEST_CASE("a process that cannot be opened is an error, not an empty result", "[live]") {
    std::string error;
    const auto result = scanProcess(0xFFFFFFF0u, {}, &error);
    CHECK_FALSE(result);
    CHECK(error.find("cannot open process") != std::string::npos);
}

TEST_CASE("a process of the other bitness is refused with a pointer to the right build", "[live]") {
#if defined(_WIN64)
    const wchar_t* other = L"C:\\Windows\\SysWOW64\\cmd.exe";
    const char* expected = "32-bit";
#else
    const wchar_t* other = L"C:\\Windows\\Sysnative\\cmd.exe";
    const char* expected = "64-bit";
#endif
    if (GetFileAttributesW(other) == INVALID_FILE_ATTRIBUTES) {
        SKIP("no process of the other bitness can be started here");
    }
    test::ChildProcess child(std::wstring(L"\"") + other + L"\" /d /q /k");
    std::string error;
    const auto result = scanProcess(child.pid(), {}, &error);
    CHECK_FALSE(result);
    CHECK(error.find(expected) != std::string::npos);
}
