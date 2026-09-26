// The command-line tool: exit codes, output forms and argument errors.

#include "ChildProcess.h"

#include <catch2/catch_test_macros.hpp>

using test::ChildProcess;
using test::Fixture;
using test::widen;

namespace {

struct Run {
    DWORD exitCode = 0;
    std::string output;
};

Run hookscan(const std::string& arguments) {
    ChildProcess child(L"\"" + widen(HOOKSCAN_CLI_EXE) + L"\" " + widen(arguments));
    Run run;
    run.exitCode = child.readAllAndWait(run.output);
    return run;
}

} // namespace

TEST_CASE("cli: a clean process exits 0 and says so", "[cli]") {
    Fixture fixture("clean");
    REQUIRE(fixture.ready());
    const Run run = hookscan("--pid " + std::to_string(fixture.pid()));
    INFO(run.output);
    CHECK(run.exitCode == 0);
    CHECK(run.output.find("hookscan_fixture.exe") != std::string::npos);
    CHECK(run.output.find("no findings") != std::string::npos);
}

TEST_CASE("cli: findings exit 1 and the report names both hooks", "[cli]") {
    Fixture fixture("hooked");
    REQUIRE(fixture.ready());
    const Run run = hookscan("--pid " + std::to_string(fixture.pid()));
    INFO(run.output);
    CHECK(run.exitCode == 1);
    CHECK(run.output.find("[inline] hookscan_fixture.exe+") != std::string::npos);
    CHECK(run.output.find("target    hookscan_fixture.exe!FixtureDetour") != std::string::npos);
    CHECK(run.output.find("[iat] hookscan_fixture.exe imports KERNEL32.dll!GetTickCount") != std::string::npos);
    CHECK(run.output.find("target    hookscan_fixture.exe!FixtureFakeTickCount") != std::string::npos);
    CHECK(run.output.find("2 findings") != std::string::npos);
}

TEST_CASE("cli: --json prints one object with every finding", "[cli]") {
    Fixture fixture("hooked");
    REQUIRE(fixture.ready());
    const Run run = hookscan("--json --pid " + std::to_string(fixture.pid()));
    INFO(run.output);
    CHECK(run.exitCode == 1);
    CHECK(run.output.starts_with("{\n"));
    CHECK(run.output.find("\"kind\": \"inline\"") != std::string::npos);
    CHECK(run.output.find("\"shape\": \"jmp\"") != std::string::npos);
    CHECK(run.output.find("\"kind\": \"iat\"") != std::string::npos);
    CHECK(run.output.find("\"function\": \"GetTickCount\"") != std::string::npos);
    CHECK(run.output.find("\"symbol\": \"FixtureFakeTickCount\"") != std::string::npos);
}

TEST_CASE("cli: --module limits the scan", "[cli]") {
    Fixture fixture("hooked");
    REQUIRE(fixture.ready());
    const Run run = hookscan("--pid " + std::to_string(fixture.pid()) + " --module ntdll.dll");
    INFO(run.output);
    CHECK(run.exitCode == 0);
    CHECK(run.output.find("1 of ") != std::string::npos);
}

TEST_CASE("cli: --self scans its own process clean", "[cli]") {
    const Run run = hookscan("--self");
    INFO(run.output);
    CHECK(run.exitCode == 0);
    CHECK(run.output.find("hookscan.exe") != std::string::npos);
}

TEST_CASE("cli: errors exit 2", "[cli]") {
    CHECK(hookscan("").exitCode == 2);
    CHECK(hookscan("--pid").exitCode == 2);
    CHECK(hookscan("--pid abc").exitCode == 2);
    CHECK(hookscan("--pid 1 --self").exitCode == 2);
    CHECK(hookscan("--frobnicate").exitCode == 2);
    CHECK(hookscan("--gap 99 --self").exitCode == 2);
    CHECK(hookscan("--name no-such-process-hookscan.exe").exitCode == 2);

    const Run unopenable = hookscan("--pid 4294967280");
    CHECK(unopenable.exitCode == 2);
    CHECK(unopenable.output.find("cannot open process") != std::string::npos);
}

TEST_CASE("cli: --help and --version exit 0", "[cli]") {
    const Run help = hookscan("--help");
    CHECK(help.exitCode == 0);
    CHECK(help.output.find("usage: hookscan") != std::string::npos);
    const Run version = hookscan("--version");
    CHECK(version.exitCode == 0);
    CHECK(version.output == "hookscan " HOOKSCAN_VERSION "\n");
}
