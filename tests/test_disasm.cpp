// Patch-shape classification on hand-encoded bytes. The live tests cover a
// jmp rel32 and an int3 in a real process; these cover every other shape the
// decoder recognizes, in both bitnesses, plus the cases it must not claim.

#include "core/Disasm.h"

#include "Bytes.h"

#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <map>
#include <vector>

using namespace hookscan;

namespace {

constexpr std::uint64_t kBase64 = 0x140001000ull;
constexpr std::uint32_t kBase32 = 0x00401000u;
constexpr std::uint64_t kTarget64 = 0x00007FFA12345678ull;
constexpr std::uint32_t kTarget32 = 0x12345678u;

// Memory outside the patch, for pointer slots the patch does not contain.
class FakeMemory : public MemoryReader {
public:
    void put(std::uint64_t address, std::uint64_t value, std::size_t size) {
        for (std::size_t i = 0; i < size; ++i) {
            bytes_[address + i] = static_cast<std::uint8_t>(value >> (8 * i));
        }
    }
    bool read(std::uint64_t address, void* out, std::size_t size) const override {
        auto* dst = static_cast<std::uint8_t*>(out);
        for (std::size_t i = 0; i < size; ++i) {
            const auto it = bytes_.find(address + i);
            if (it == bytes_.end()) {
                return false;
            }
            dst[i] = it->second;
        }
        return true;
    }

private:
    std::map<std::uint64_t, std::uint8_t> bytes_;
};

std::vector<std::uint8_t> withImm64(std::vector<std::uint8_t> head, std::uint64_t imm, std::vector<std::uint8_t> tail = {}) {
    const std::size_t at = head.size();
    head.resize(at + 8);
    test::put64(head, at, imm);
    head.insert(head.end(), tail.begin(), tail.end());
    return head;
}

std::vector<std::uint8_t> withImm32(std::vector<std::uint8_t> head, std::uint32_t imm, std::vector<std::uint8_t> tail = {}) {
    const std::size_t at = head.size();
    head.resize(at + 4);
    test::put32(head, at, imm);
    head.insert(head.end(), tail.begin(), tail.end());
    return head;
}

PatchAnalysis analyze(Bitness bitness, const std::vector<std::uint8_t>& bytes, std::uint64_t base, const MemoryReader* memory = nullptr) {
    const Disassembler d(bitness);
    const CodeView live{bytes, base};
    return d.analyze(live, base, base + bytes.size(), memory);
}

} // namespace

TEST_CASE("jmp [rip+0] with the target inline is an indirect jump to that target", "[disasm]") {
    // FF 25 00000000 <imm64>: the 14-byte absolute jump.
    const auto bytes = withImm64({0xFF, 0x25, 0x00, 0x00, 0x00, 0x00}, kTarget64);
    const auto a = analyze(Bitness::X64, bytes, kBase64);
    CHECK(a.shape == PatchShape::JumpIndirect);
    REQUIRE(a.target);
    CHECK(*a.target == kTarget64);
}

TEST_CASE("jmp [rip+disp] reads a slot outside the patch from memory", "[disasm]") {
    // FF 25 00000100: the slot is at next-instruction + 0x100.
    const auto bytes = withImm32({0xFF, 0x25}, 0x100);
    const std::uint64_t slot = kBase64 + 6 + 0x100;

    FakeMemory memory;
    memory.put(slot, kTarget64, 8);
    const auto a = analyze(Bitness::X64, bytes, kBase64, &memory);
    CHECK(a.shape == PatchShape::JumpIndirect);
    REQUIRE(a.target);
    CHECK(*a.target == kTarget64);

    SECTION("with no memory to read, the shape stands and the target is unknown") {
        const auto b = analyze(Bitness::X64, bytes, kBase64, nullptr);
        CHECK(b.shape == PatchShape::JumpIndirect);
        CHECK_FALSE(b.target);
    }
}

TEST_CASE("call [rip+disp] is an indirect call", "[disasm]") {
    // FF 15 00000002; jmp short +8; <imm64>. The slot is the imm64.
    auto bytes = withImm32({0xFF, 0x15}, 2, {0xEB, 0x08});
    bytes = withImm64(bytes, kTarget64);
    const Disassembler d(Bitness::X64);
    const auto a = d.analyze(CodeView{bytes, kBase64}, kBase64, kBase64 + 6, nullptr);
    CHECK(a.shape == PatchShape::CallIndirect);
    REQUIRE(a.target);
    CHECK(*a.target == kTarget64);
}

TEST_CASE("x86 jmp [abs32] reads the absolute slot", "[disasm]") {
    const std::uint32_t slot = 0x00500000u;
    const auto bytes = withImm32({0xFF, 0x25}, slot);
    FakeMemory memory;
    memory.put(slot, kTarget32, 4);
    const auto a = analyze(Bitness::X86, bytes, kBase32, &memory);
    CHECK(a.shape == PatchShape::JumpIndirect);
    REQUIRE(a.target);
    CHECK(*a.target == kTarget32);
}

TEST_CASE("call rel32 is a relative call", "[disasm]") {
    const std::uint32_t rel = 0x1000;
    const auto bytes = withImm32({0xE8}, rel);
    const auto a = analyze(Bitness::X64, bytes, kBase64);
    CHECK(a.shape == PatchShape::CallRelative);
    REQUIRE(a.target);
    CHECK(*a.target == kBase64 + 5 + rel);
}

TEST_CASE("push imm32; ret is a push-return", "[disasm]") {
    const auto bytes = withImm32({0x68}, kTarget32, {0xC3});
    const auto a = analyze(Bitness::X86, bytes, kBase32);
    CHECK(a.shape == PatchShape::PushReturn);
    REQUIRE(a.target);
    CHECK(*a.target == kTarget32);
}

TEST_CASE("x64 push imm32; mov dword [rsp+4], imm32; ret joins both halves", "[disasm]") {
    const auto lo = static_cast<std::uint32_t>(kTarget64 & 0xFFFFFFFFu);
    const auto hi = static_cast<std::uint32_t>(kTarget64 >> 32);
    auto bytes = withImm32({0x68}, lo, {0xC7, 0x44, 0x24, 0x04});
    bytes = withImm32(std::move(bytes), hi, {0xC3});

    const auto a = analyze(Bitness::X64, bytes, kBase64);
    CHECK(a.shape == PatchShape::PushReturn);
    REQUIRE(a.target);
    CHECK(*a.target == kTarget64);
}

TEST_CASE("x64 push imm32 with the low half's top bit set is not sign-extended", "[disasm]") {
    // push sign-extends its imm32 to 64 bits; the target keeps only the low half.
    const std::uint64_t target = 0x00007FFA9ABCDEF0ull;
    const auto lo = static_cast<std::uint32_t>(target & 0xFFFFFFFFu);
    const auto hi = static_cast<std::uint32_t>(target >> 32);
    auto bytes = withImm32({0x68}, lo, {0xC7, 0x44, 0x24, 0x04});
    bytes = withImm32(std::move(bytes), hi, {0xC3});

    const auto a = analyze(Bitness::X64, bytes, kBase64);
    CHECK(a.shape == PatchShape::PushReturn);
    REQUIRE(a.target);
    CHECK(*a.target == target);
}

TEST_CASE("mov reg, imm; jmp reg is a register jump", "[disasm]") {
    SECTION("x64 mov rax, imm64; jmp rax") {
        const auto bytes = withImm64({0x48, 0xB8}, kTarget64, {0xFF, 0xE0});
        const auto a = analyze(Bitness::X64, bytes, kBase64);
        CHECK(a.shape == PatchShape::RegisterJump);
        REQUIRE(a.target);
        CHECK(*a.target == kTarget64);
    }
    SECTION("x64 mov r11, imm64; jmp r11") {
        const auto bytes = withImm64({0x49, 0xBB}, kTarget64, {0x41, 0xFF, 0xE3});
        const auto a = analyze(Bitness::X64, bytes, kBase64);
        CHECK(a.shape == PatchShape::RegisterJump);
        REQUIRE(a.target);
        CHECK(*a.target == kTarget64);
    }
    SECTION("x86 mov eax, imm32; jmp eax") {
        const auto bytes = withImm32({0xB8}, kTarget32, {0xFF, 0xE0});
        const auto a = analyze(Bitness::X86, bytes, kBase32);
        CHECK(a.shape == PatchShape::RegisterJump);
        REQUIRE(a.target);
        CHECK(*a.target == kTarget32);
    }
}

TEST_CASE("mov rax, imm64; call rax is a register call", "[disasm]") {
    const auto bytes = withImm64({0x48, 0xB8}, kTarget64, {0xFF, 0xD0});
    const auto a = analyze(Bitness::X64, bytes, kBase64);
    CHECK(a.shape == PatchShape::RegisterCall);
    REQUIRE(a.target);
    CHECK(*a.target == kTarget64);
}

TEST_CASE("mov rax, imm64; push rax; ret is a push-return", "[disasm]") {
    const auto bytes = withImm64({0x48, 0xB8}, kTarget64, {0x50, 0xC3});
    const auto a = analyze(Bitness::X64, bytes, kBase64);
    CHECK(a.shape == PatchShape::PushReturn);
    REQUIRE(a.target);
    CHECK(*a.target == kTarget64);
}

TEST_CASE("the x86 hot-patch short hop is followed to the real jump", "[disasm]") {
    // Five bytes of padding before the function hold "jmp rel32"; the
    // function's first two bytes are "jmp short -7" back into the padding.
    const std::uint32_t pad = kBase32 - 5;
    const std::uint32_t rel = 0x00100000u;
    auto bytes = withImm32({0xE9}, rel, {0xEB, 0xF9});

    const Disassembler d(Bitness::X86);
    const auto a = d.analyze(CodeView{bytes, pad}, kBase32, kBase32 + 2, nullptr);
    CHECK(a.shape == PatchShape::JumpRelative);
    REQUIRE(a.target);
    CHECK(*a.target == static_cast<std::uint64_t>(pad) + 5 + rel);
}

TEST_CASE("shapes that are not redirections are not claimed as one", "[disasm]") {
    SECTION("the register loaded is not the register jumped through") {
        const auto bytes = withImm64({0x48, 0xB8}, kTarget64, {0xFF, 0xE1}); // jmp rcx
        const auto a = analyze(Bitness::X64, bytes, kBase64);
        CHECK(a.shape == PatchShape::Other);
        CHECK_FALSE(a.target);
    }
    SECTION("an ordinary instruction") {
        const std::vector<std::uint8_t> bytes{0x48, 0x89, 0x5C, 0x24, 0x08}; // mov [rsp+8], rbx
        const auto a = analyze(Bitness::X64, bytes, kBase64);
        CHECK(a.shape == PatchShape::Other);
    }
    SECTION("push imm32 not followed by ret") {
        const auto bytes = withImm32({0x68}, kTarget32, {0x90});
        const auto a = analyze(Bitness::X86, bytes, kBase32);
        CHECK(a.shape == PatchShape::Other);
    }
    SECTION("bytes that do not decode") {
        const std::vector<std::uint8_t> bytes{0x06}; // push es: invalid in 64-bit mode
        const auto a = analyze(Bitness::X64, bytes, kBase64);
        CHECK(a.shape == PatchShape::Undecodable);
        CHECK(a.instructions.empty());
    }
}
