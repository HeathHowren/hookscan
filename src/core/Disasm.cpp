#include "core/Disasm.h"

#include <cstring>

// Zydis is C and its headers are clean at /W4, but they are third-party, so
// keep the project's warnings-as-errors off them.
#pragma warning(push, 3)
#include <Zydis/Zydis.h>
#pragma warning(pop)

namespace hookscan {

namespace {

struct Decoded {
    ZydisDecodedInstruction instr{};
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
    std::uint64_t address = 0;

    [[nodiscard]] const ZydisDecodedOperand* firstVisible() const {
        return instr.operand_count_visible > 0 ? &operands[0] : nullptr;
    }
};

bool isJump(const Decoded& d) {
    return d.instr.mnemonic == ZYDIS_MNEMONIC_JMP;
}

bool isCall(const Decoded& d) {
    return d.instr.mnemonic == ZYDIS_MNEMONIC_CALL;
}

bool isReturn(const Decoded& d) {
    return d.instr.mnemonic == ZYDIS_MNEMONIC_RET;
}

} // namespace

const char* shapeName(PatchShape shape) {
    switch (shape) {
    case PatchShape::JumpRelative:
        return "jmp";
    case PatchShape::CallRelative:
        return "call";
    case PatchShape::JumpIndirect:
        return "jmp-indirect";
    case PatchShape::CallIndirect:
        return "call-indirect";
    case PatchShape::PushReturn:
        return "push-ret";
    case PatchShape::RegisterJump:
        return "jmp-register";
    case PatchShape::RegisterCall:
        return "call-register";
    case PatchShape::Breakpoint:
        return "int3";
    case PatchShape::Other:
        return "other";
    case PatchShape::Undecodable:
        return "undecodable";
    }
    return "other";
}

struct Disassembler::Impl {
    ZydisDecoder decoder{};
    ZydisFormatter formatter{};
    ZydisMachineMode mode = ZYDIS_MACHINE_MODE_LONG_64;

    std::optional<Decoded> decode(const CodeView& view, std::uint64_t address) const {
        const auto bytes = view.from(address);
        if (bytes.empty()) {
            return std::nullopt;
        }
        Decoded d;
        d.address = address;
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, bytes.data(), bytes.size(), &d.instr, d.operands))) {
            return std::nullopt;
        }
        return d;
    }

    std::string format(const Decoded& d) const {
        char text[256];
        if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&formatter, &d.instr, d.operands, d.instr.operand_count_visible, text, sizeof(text),
                                                         d.address, ZYAN_NULL))) {
            return text;
        }
        return "??";
    }

    std::optional<std::uint64_t> relativeTarget(const Decoded& d) const {
        const ZydisDecodedOperand* op = d.firstVisible();
        if (!op || op->type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !op->imm.is_relative) {
            return std::nullopt;
        }
        ZyanU64 target = 0;
        if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&d.instr, op, d.address, &target))) {
            return std::nullopt;
        }
        return target;
    }

    // The address a "jmp [x]" or "call [x]" reads its target from, when that
    // address is fixed (RIP-relative or absolute, no base or index register).
    std::optional<std::uint64_t> pointerSlot(const Decoded& d) const {
        const ZydisDecodedOperand* op = d.firstVisible();
        if (!op || op->type != ZYDIS_OPERAND_TYPE_MEMORY || op->mem.index != ZYDIS_REGISTER_NONE) {
            return std::nullopt;
        }
        if (op->mem.base == ZYDIS_REGISTER_RIP || op->mem.base == ZYDIS_REGISTER_EIP) {
            ZyanU64 slot = 0;
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&d.instr, op, d.address, &slot))) {
                return slot;
            }
            return std::nullopt;
        }
        if (op->mem.base == ZYDIS_REGISTER_NONE && op->mem.segment != ZYDIS_REGISTER_FS && op->mem.segment != ZYDIS_REGISTER_GS) {
            auto slot = static_cast<std::uint64_t>(op->mem.disp.value);
            if (mode != ZYDIS_MACHINE_MODE_LONG_64) {
                slot &= 0xFFFFFFFFull;
            }
            return slot;
        }
        return std::nullopt;
    }

    ZydisRegister widest(ZydisRegister reg) const {
        return ZydisRegisterGetLargestEnclosing(mode, reg);
    }
};

Disassembler::Disassembler(Bitness bitness) : impl_(std::make_unique<Impl>()), bitness_(bitness) {
    if (bitness == Bitness::X64) {
        impl_->mode = ZYDIS_MACHINE_MODE_LONG_64;
        ZydisDecoderInit(&impl_->decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    } else {
        impl_->mode = ZYDIS_MACHINE_MODE_LEGACY_32;
        ZydisDecoderInit(&impl_->decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
    }
    ZydisFormatterInit(&impl_->formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&impl_->formatter, ZYDIS_FORMATTER_PROP_HEX_UPPERCASE, ZYAN_TRUE);
}

Disassembler::~Disassembler() = default;

std::optional<Instruction> Disassembler::decode(std::span<const std::uint8_t> bytes, std::uint64_t address) const {
    const auto d = impl_->decode(CodeView{bytes, address}, address);
    if (!d) {
        return std::nullopt;
    }
    return Instruction{address, d->instr.length, impl_->format(*d)};
}

std::uint64_t Disassembler::instructionStart(const CodeView& original, const CodeView& live, std::uint64_t regionBegin,
                                             std::optional<std::uint64_t> functionBegin) const {
    if (functionBegin && *functionBegin <= regionBegin && regionBegin - *functionBegin < 0x10000 && original.contains(*functionBegin)) {
        std::uint64_t pc = *functionBegin;
        while (pc < regionBegin) {
            const auto d = impl_->decode(original, pc);
            if (!d) {
                break;
            }
            if (pc + d->instr.length > regionBegin) {
                return pc;
            }
            pc += d->instr.length;
        }
        if (pc == regionBegin) {
            return pc;
        }
    }

    for (std::uint64_t back = 1; back <= 14 && regionBegin >= original.address + back; ++back) {
        const std::uint64_t at = regionBegin - back;
        const auto before = impl_->decode(original, at);
        const auto after = impl_->decode(live, at);
        if (!before || !after || at + before->instr.length <= regionBegin) {
            continue;
        }
        const bool branch = isJump(*after) || isCall(*after) || after->instr.mnemonic == ZYDIS_MNEMONIC_PUSH;
        if (branch && before->instr.mnemonic == after->instr.mnemonic && before->instr.length == after->instr.length) {
            return at;
        }
    }
    return regionBegin;
}

PatchAnalysis Disassembler::analyze(const CodeView& live, std::uint64_t start, std::uint64_t regionEnd, const MemoryReader* memory) const {
    PatchAnalysis a;
    a.start = start;
    a.end = regionEnd;

    std::uint64_t pc = start;
    for (int i = 0; i < 8; ++i) {
        const auto d = impl_->decode(live, pc);
        if (!d) {
            break;
        }
        a.instructions.push_back({pc, d->instr.length, impl_->format(*d)});
        pc += d->instr.length;
        if (pc >= regionEnd) {
            break;
        }
    }
    if (!a.instructions.empty()) {
        a.end = std::max(pc, regionEnd);
    }

    const std::uint32_t pointerSize = bitness_ == Bitness::X64 ? 8 : 4;
    auto readPointer = [&](std::uint64_t address) -> std::optional<std::uint64_t> {
        std::uint64_t value = 0;
        const auto inside = live.from(address);
        if (inside.size() >= pointerSize) {
            std::memcpy(&value, inside.data(), pointerSize);
            return value;
        }
        if (memory && memory->read(address, &value, pointerSize)) {
            return value;
        }
        return std::nullopt;
    };

    // Follow short hops that stay near the patch: the classic x86 hot-patch
    // writes "jmp short -5" over "mov edi, edi" and the real jmp into the
    // padding before the function.
    std::uint64_t at = start;
    for (int hop = 0; hop < 3; ++hop) {
        const auto d0 = impl_->decode(live, at);
        if (!d0) {
            a.shape = hop == 0 ? PatchShape::Undecodable : a.shape;
            return a;
        }
        const auto d1 = impl_->decode(live, at + d0->instr.length);

        if (d0->instr.mnemonic == ZYDIS_MNEMONIC_INT3) {
            a.shape = PatchShape::Breakpoint;
            return a;
        }

        if (isJump(*d0) || isCall(*d0)) {
            if (const auto target = impl_->relativeTarget(*d0)) {
                a.shape = isJump(*d0) ? PatchShape::JumpRelative : PatchShape::CallRelative;
                a.target = *target;
                const bool nearby = *target + 32 >= start && *target < a.end + 32 && *target != at;
                if (isJump(*d0) && nearby && live.contains(*target)) {
                    at = *target;
                    continue;
                }
                return a;
            }
            if (const auto slot = impl_->pointerSlot(*d0)) {
                a.shape = isJump(*d0) ? PatchShape::JumpIndirect : PatchShape::CallIndirect;
                a.target = readPointer(*slot);
                return a;
            }
            a.shape = PatchShape::Other;
            return a;
        }

        const ZydisDecodedOperand* op0 = d0->firstVisible();
        if (d0->instr.mnemonic == ZYDIS_MNEMONIC_PUSH && op0 && op0->type == ZYDIS_OPERAND_TYPE_IMMEDIATE && d1) {
            std::uint64_t value = op0->imm.is_signed ? static_cast<std::uint64_t>(op0->imm.value.s) : op0->imm.value.u;
            if (bitness_ == Bitness::X86) {
                value &= 0xFFFFFFFFull;
            }
            if (isReturn(*d1)) {
                a.shape = PatchShape::PushReturn;
                a.target = value;
                return a;
            }
            // x64: push imm32; mov dword ptr [rsp+4], imm32; ret
            const auto d2 = impl_->decode(live, d1->address + d1->instr.length);
            const ZydisDecodedOperand* m = d1->firstVisible();
            if (bitness_ == Bitness::X64 && d2 && isReturn(*d2) && d1->instr.mnemonic == ZYDIS_MNEMONIC_MOV && m &&
                m->type == ZYDIS_OPERAND_TYPE_MEMORY && m->mem.base == ZYDIS_REGISTER_RSP && m->mem.disp.value == 4 &&
                d1->instr.operand_count_visible >= 2 && d1->operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                a.shape = PatchShape::PushReturn;
                a.target = (value & 0xFFFFFFFFull) | (static_cast<std::uint64_t>(d1->operands[1].imm.value.u & 0xFFFFFFFFull) << 32);
                return a;
            }
        }

        if (d0->instr.mnemonic == ZYDIS_MNEMONIC_MOV && op0 && op0->type == ZYDIS_OPERAND_TYPE_REGISTER && d0->instr.operand_count_visible >= 2 &&
            d0->operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && d1) {
            const ZydisRegister reg = impl_->widest(op0->reg.value);
            std::uint64_t value = d0->operands[1].imm.value.u;
            if (op0->size == 32) {
                value &= 0xFFFFFFFFull;
            }
            const ZydisDecodedOperand* op1 = d1->firstVisible();
            const bool usesReg = op1 && op1->type == ZYDIS_OPERAND_TYPE_REGISTER && impl_->widest(op1->reg.value) == reg;
            if (usesReg && (isJump(*d1) || isCall(*d1))) {
                a.shape = isJump(*d1) ? PatchShape::RegisterJump : PatchShape::RegisterCall;
                a.target = value;
                return a;
            }
            if (usesReg && d1->instr.mnemonic == ZYDIS_MNEMONIC_PUSH) {
                const auto d2 = impl_->decode(live, d1->address + d1->instr.length);
                if (d2 && isReturn(*d2)) {
                    a.shape = PatchShape::PushReturn;
                    a.target = value;
                    return a;
                }
            }
        }

        a.shape = hop == 0 ? PatchShape::Other : a.shape;
        return a;
    }
    return a;
}

} // namespace hookscan
