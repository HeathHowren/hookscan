#include "Bytes.h"

#include "core/ApiSet.h"

#include <catch2/catch_test_macros.hpp>

using namespace hookscan;
using namespace test;

namespace {

// A version 6 schema, built by hand in the layout Windows 10 and 11 use.
class SchemaBuilder {
public:
    struct Value {
        std::string importer;
        std::string host;
    };

    void add(const std::string& name, std::vector<Value> values) { sets_.push_back({name, std::move(values)}); }

    std::vector<std::uint8_t> build() const {
        std::vector<std::uint8_t> b(0x4000, 0);
        const std::uint32_t entries = 28;
        const std::uint32_t valuesStart = entries + static_cast<std::uint32_t>(sets_.size()) * 24;
        std::uint32_t valueCursor = valuesStart;
        for (const auto& set : sets_) {
            valueCursor += static_cast<std::uint32_t>(set.values.size()) * 20;
        }
        std::uint32_t strings = valueCursor;
        auto string = [&](const std::string& s) {
            const std::uint32_t at = strings;
            for (std::size_t i = 0; i < s.size(); ++i) {
                put16(b, at + i * 2, static_cast<std::uint16_t>(s[i]));
            }
            strings += static_cast<std::uint32_t>(s.size() * 2);
            return at;
        };

        put32(b, 0, 6);
        put32(b, 12, static_cast<std::uint32_t>(sets_.size()));
        put32(b, 16, entries);
        valueCursor = valuesStart;
        for (std::size_t i = 0; i < sets_.size(); ++i) {
            const auto& set = sets_[i];
            const std::uint32_t e = entries + static_cast<std::uint32_t>(i) * 24;
            put32(b, e + 4, string(set.name));
            put32(b, e + 8, static_cast<std::uint32_t>(set.name.size() * 2));
            put32(b, e + 12, static_cast<std::uint32_t>(set.name.rfind('-') * 2));
            put32(b, e + 16, valueCursor);
            put32(b, e + 20, static_cast<std::uint32_t>(set.values.size()));
            for (const Value& v : set.values) {
                put32(b, valueCursor + 4, v.importer.empty() ? 0 : string(v.importer));
                put32(b, valueCursor + 8, static_cast<std::uint32_t>(v.importer.size() * 2));
                put32(b, valueCursor + 12, v.host.empty() ? 0 : string(v.host));
                put32(b, valueCursor + 16, static_cast<std::uint32_t>(v.host.size() * 2));
                valueCursor += 20;
            }
        }
        put32(b, 4, strings);
        b.resize(strings);
        return b;
    }

private:
    struct Set {
        std::string name;
        std::vector<Value> values;
    };
    std::vector<Set> sets_;
};

ApiSetResolver sample() {
    SchemaBuilder schema;
    schema.add("api-ms-win-core-test-l1-1-2", {{"", "kernelbase.dll"}, {"kernel32.dll", "kernel32impl.dll"}});
    schema.add("ext-ms-win-missing-l1-1-0", {{"", ""}});
    return ApiSetResolver::fromSchema(schema.build());
}

} // namespace

TEST_CASE("API set names are recognized by prefix", "[apiset]") {
    CHECK(ApiSetResolver::isApiSetName("api-ms-win-core-synch-l1-2-0.dll"));
    CHECK(ApiSetResolver::isApiSetName("EXT-MS-WIN-foo-l1-1-0.dll"));
    CHECK_FALSE(ApiSetResolver::isApiSetName("kernel32.dll"));
    CHECK_FALSE(ApiSetResolver::isApiSetName("api"));
    CHECK_FALSE(ApiSetResolver::isApiSetName(""));
}

TEST_CASE("a set resolves to its default host, ignoring the minor version", "[apiset]") {
    const auto resolver = sample();
    REQUIRE(resolver.size() == 2);
    CHECK(resolver.resolve("api-ms-win-core-test-l1-1-2.dll", "game.exe") == "kernelbase.dll");
    CHECK(resolver.resolve("API-MS-WIN-CORE-TEST-L1-1-0.DLL", "game.exe") == "kernelbase.dll");
    CHECK(resolver.resolve("api-ms-win-core-test-l1-1-0", "") == "kernelbase.dll");
}

TEST_CASE("an importer with an exception gets its own host", "[apiset]") {
    const auto resolver = sample();
    CHECK(resolver.resolve("api-ms-win-core-test-l1-1-0.dll", "KERNEL32.DLL") == "kernel32impl.dll");
}

TEST_CASE("a set with no host resolves to empty, an unknown set to nothing", "[apiset]") {
    const auto resolver = sample();
    CHECK(resolver.resolve("ext-ms-win-missing-l1-1-0.dll", "x.dll") == "");
    CHECK_FALSE(resolver.resolve("api-ms-win-core-nothere-l1-1-0.dll", "x.dll"));
    CHECK_FALSE(resolver.resolve("kernel32.dll", "x.dll"));
}

TEST_CASE("schemas that are not version 6 or are truncated give an empty resolver", "[apiset]") {
    SchemaBuilder builder;
    builder.add("api-ms-win-core-test-l1-1-0", {{"", "kernelbase.dll"}});
    auto bytes = builder.build();

    auto wrongVersion = bytes;
    put32(wrongVersion, 0, 4);
    CHECK(ApiSetResolver::fromSchema(wrongVersion).empty());

    const std::vector<std::uint8_t> truncated(bytes.begin(), bytes.begin() + 20);
    CHECK(ApiSetResolver::fromSchema(truncated).empty());
    CHECK(ApiSetResolver::fromSchema({}).empty());
}

TEST_CASE("the system schema maps common CRT and core sets", "[apiset]") {
    const ApiSetResolver& system = ApiSetResolver::system();
    REQUIRE_FALSE(system.empty());
    CHECK(system.resolve("api-ms-win-core-synch-l1-2-0.dll", "game.exe") == "kernelbase.dll");
    CHECK(system.resolve("api-ms-win-crt-runtime-l1-1-0.dll", "game.exe") == "ucrtbase.dll");
}
