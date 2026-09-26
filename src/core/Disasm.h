#pragma once

#include "core/MemoryReader.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace hookscan {

enum class Bitness { X86, X64 };

// Bytes and the address the first of them lives at.
struct CodeView {
    std::span<const std::uint8_t> bytes;
    std::uint64_t address = 0;

    [[nodiscard]] bool contains(std::uint64_t at) const { return at >= address && at - address < bytes.size(); }
    // The bytes from `at` to the end, or an empty span when `at` is outside.
    [[nodiscard]] std::span<const std::uint8_t> from(std::uint64_t at) const {
        return contains(at) ? bytes.subspan(static_cast<std::size_t>(at - address)) : std::span<const std::uint8_t>{};
    }
};

struct Instruction {
    std::uint64_t address = 0;
    std::uint8_t length = 0;
    std::string text; // Intel syntax, branch targets as absolute addresses
};

// How a patch transfers control, when it does.
enum class PatchShape {
    JumpRelative,  // jmp rel8/rel32
    CallRelative,  // call rel32
    JumpIndirect,  // jmp [rip+disp] or jmp [abs], including the 14-byte "FF 25 00000000 <imm64>" form
    CallIndirect,  // call [rip+disp] or call [abs]
    PushReturn,    // push imm32; ret (with "mov dword [rsp+4], hi" on x64), or mov reg, imm; push reg; ret
    RegisterJump,  // mov reg, imm; jmp reg
    RegisterCall,  // mov reg, imm; call reg
    Breakpoint,    // int3, usually a debugger's software breakpoint
    Other,         // decodes, but is not a recognizable redirection
    Undecodable,   // the first bytes do not decode
};

[[nodiscard]] const char* shapeName(PatchShape shape);

struct PatchAnalysis {
    std::uint64_t start = 0; // first decoded instruction
    std::uint64_t end = 0;   // end of the last instruction that overlaps the changed bytes
    std::vector<Instruction> instructions;
    PatchShape shape = PatchShape::Undecodable;
    std::optional<std::uint64_t> target; // where control goes, when the shape says
};

// A thin layer over Zydis. The Zydis types stay inside Disasm.cpp.
class Disassembler {
public:
    explicit Disassembler(Bitness bitness);
    ~Disassembler();
    Disassembler(const Disassembler&) = delete;
    Disassembler& operator=(const Disassembler&) = delete;

    [[nodiscard]] Bitness bitness() const { return bitness_; }

    [[nodiscard]] std::optional<Instruction> decode(std::span<const std::uint8_t> bytes, std::uint64_t address) const;

    // The address to start decoding a changed region at. A patch rarely
    // changes the first byte of the instruction it replaces on x64 (both
    // "mov [rsp+8], rbx" and "mov rax, imm64" start with 48), so the first
    // differing byte is often inside the new instruction.
    //
    // With `functionBegin` (from x64 .pdata), the original code is decoded
    // linearly from the function start, and the instruction that holds
    // `regionBegin` is where the patch starts. Without it, a short back-scan
    // accepts an earlier start only where the original and live bytes decode
    // to the same branch mnemonic and length there, which is the "only the
    // displacement changed" case. Otherwise the region start is used as is.
    [[nodiscard]] std::uint64_t instructionStart(const CodeView& original, const CodeView& live, std::uint64_t regionBegin,
                                                 std::optional<std::uint64_t> functionBegin) const;

    // Decodes the live bytes from `start` until the changed bytes ending at
    // `regionEnd` are covered, and works out where control goes. Pointer
    // operands (jmp [rip+disp]) are read from `live` when they fall inside it,
    // and from `memory` otherwise; `memory` may be null.
    [[nodiscard]] PatchAnalysis analyze(const CodeView& live, std::uint64_t start, std::uint64_t regionEnd, const MemoryReader* memory) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    Bitness bitness_;
};

} // namespace hookscan
