#include "core/Report.h"

#include <cstdio>

namespace hookscan {

namespace {

std::string hex(std::uint64_t value) {
    char text[24];
    std::snprintf(text, sizeof(text), "0x%llX", static_cast<unsigned long long>(value));
    return text;
}

std::string hexBytes(const std::vector<std::uint8_t>& bytes, std::size_t limit) {
    std::string out;
    char text[4];
    for (std::size_t i = 0; i < bytes.size() && i < limit; ++i) {
        std::snprintf(text, sizeof(text), "%02X", bytes[i]);
        if (!out.empty()) {
            out += ' ';
        }
        out += text;
    }
    if (bytes.size() > limit) {
        out += " ...";
    }
    return out;
}

const char* archName(Bitness bitness) {
    return bitness == Bitness::X64 ? "x64" : "x86";
}

std::string where(const Finding& f) {
    return f.module.empty() ? hex(f.address) : f.module + "+" + hex(f.address - f.moduleBase);
}

void line(std::string& out, const char* label, const std::string& value) {
    char text[16];
    std::snprintf(text, sizeof(text), "  %-9s ", label);
    out += text;
    out += value;
    out += '\n';
}

std::string quoted(std::string_view text) {
    return "\"" + jsonEscape(text) + "\"";
}

std::string addressJson(const AddressInfo& a) {
    std::string out = "{\"address\": " + quoted(hex(a.address)) + ", \"text\": " + quoted(a.text());
    if (a.inModule()) {
        out += ", \"module\": " + quoted(a.module) + ", \"offset\": " + quoted(hex(a.offset));
        if (!a.symbol.empty()) {
            out += ", \"symbol\": " + quoted(a.symbol);
        }
    } else {
        out += ", \"memory\": " + quoted(a.memory);
        if (!a.file.empty()) {
            out += ", \"file\": " + quoted(a.file);
        }
    }
    return out + "}";
}

} // namespace

std::string jsonEscape(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (const char c : text) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char escaped[8];
                std::snprintf(escaped, sizeof(escaped), "\\u%04X", static_cast<unsigned>(c));
                out += escaped;
            } else {
                out += c;
            }
        }
    }
    return out;
}

std::string formatText(const ScanResult& result, bool showNotes) {
    std::string out = "hookscan " HOOKSCAN_VERSION ": pid " + std::to_string(result.pid) + " (" + result.processName + ", " +
                      archName(result.bitness) + "), " + std::to_string(result.modulesScanned) + " of " + std::to_string(result.modulesListed) +
                      " modules scanned\n";

    for (const Finding& f : result.findings) {
        out += '\n';
        switch (f.kind) {
        case FindingKind::InlinePatch:
            out += "[inline] " + where(f) + " in " + f.section + ", " + std::to_string(f.size) + (f.size == 1 ? " byte\n" : " bytes\n");
            line(out, "original", hexBytes(f.original, 32));
            line(out, "current", hexBytes(f.current, 32));
            for (std::size_t i = 0; i < f.instructions.size(); ++i) {
                line(out, i == 0 ? "code" : "", f.instructions[i].text);
            }
            if (f.target) {
                line(out, "target", f.target->text());
            }
            break;
        case FindingKind::IatHook:
            out += "[iat] " + f.module + " imports " + f.importedModule + "!" + f.function + (f.delayLoad ? " (delay-load)\n" : "\n");
            line(out, "slot", where(f));
            if (f.expected) {
                line(out, "expected", f.expected->text());
            }
            if (f.target) {
                line(out, "target", f.target->text());
            }
            break;
        case FindingKind::EatHook:
            out += "[eat] " + f.module + " exports " + f.function + "\n";
            line(out, "slot", where(f));
            if (f.expected) {
                line(out, "expected", f.expected->text());
            }
            if (f.target) {
                line(out, "target", f.target->text());
            }
            break;
        case FindingKind::UnbackedModule:
        case FindingKind::ImageMismatch:
        case FindingKind::UnlistedImage:
        case FindingKind::PrivateImage:
            out += "[" + std::string(kindName(f.kind)) + "] " + (f.module.empty() ? std::string() : f.module + " ") + "at " + hex(f.address) +
                   ", " + hex(f.size) + " bytes\n";
            if (!f.path.empty()) {
                line(out, "file", f.path);
            }
            break;
        }
        if (!f.detail.empty()) {
            line(out, "note", f.detail);
        }
    }

    if (showNotes && !result.notes.empty()) {
        out += '\n';
        for (const std::string& n : result.notes) {
            out += "note: " + n + "\n";
        }
    }
    out += '\n';
    out += result.findings.empty() ? std::string("no findings") : std::to_string(result.findings.size()) + (result.findings.size() == 1 ? " finding" : " findings");
    if (!showNotes && !result.notes.empty()) {
        out += ", " + std::to_string(result.notes.size()) + (result.notes.size() == 1 ? " note" : " notes") + " (--notes shows them)";
    }
    out += '\n';
    return out;
}

std::string formatJson(const ScanResult& result) {
    std::string out = "{\n";
    out += "  \"tool\": \"hookscan\",\n";
    out += "  \"version\": \"" HOOKSCAN_VERSION "\",\n";
    out += "  \"pid\": " + std::to_string(result.pid) + ",\n";
    out += "  \"process\": " + quoted(result.processName) + ",\n";
    out += "  \"arch\": \"" + std::string(archName(result.bitness)) + "\",\n";
    out += "  \"modulesListed\": " + std::to_string(result.modulesListed) + ",\n";
    out += "  \"modulesScanned\": " + std::to_string(result.modulesScanned) + ",\n";
    out += "  \"findings\": [";
    for (std::size_t i = 0; i < result.findings.size(); ++i) {
        const Finding& f = result.findings[i];
        out += i == 0 ? "\n" : ",\n";
        out += "    {\"kind\": " + quoted(kindName(f.kind));
        if (!f.module.empty()) {
            out += ", \"module\": " + quoted(f.module);
        }
        if (f.moduleBase != 0) {
            out += ", \"moduleBase\": " + quoted(hex(f.moduleBase)) + ", \"rva\": " + quoted(hex(f.address - f.moduleBase));
        }
        out += ", \"address\": " + quoted(hex(f.address)) + ", \"size\": " + std::to_string(f.size);
        switch (f.kind) {
        case FindingKind::InlinePatch: {
            out += ", \"section\": " + quoted(f.section);
            out += ", \"original\": " + quoted(hexBytes(f.original, f.original.size()));
            out += ", \"current\": " + quoted(hexBytes(f.current, f.current.size()));
            out += ", \"shape\": " + quoted(shapeName(f.shape));
            out += ", \"instructions\": [";
            for (std::size_t k = 0; k < f.instructions.size(); ++k) {
                out += (k == 0 ? "" : ", ") + quoted(f.instructions[k].text);
            }
            out += "]";
            break;
        }
        case FindingKind::IatHook:
            out += ", \"import\": " + quoted(f.importedModule) + ", \"function\": " + quoted(f.function) +
                   ", \"delayLoad\": " + (f.delayLoad ? "true" : "false");
            break;
        case FindingKind::EatHook:
            out += ", \"function\": " + quoted(f.function);
            break;
        case FindingKind::UnbackedModule:
        case FindingKind::ImageMismatch:
        case FindingKind::UnlistedImage:
        case FindingKind::PrivateImage:
            if (!f.path.empty()) {
                out += ", \"file\": " + quoted(f.path);
            }
            break;
        }
        if (f.expected) {
            out += ", \"expected\": " + addressJson(*f.expected);
        }
        if (f.target) {
            out += ", \"target\": " + addressJson(*f.target);
        }
        if (!f.detail.empty()) {
            out += ", \"detail\": " + quoted(f.detail);
        }
        out += "}";
    }
    out += result.findings.empty() ? "],\n" : "\n  ],\n";
    out += "  \"notes\": [";
    for (std::size_t i = 0; i < result.notes.size(); ++i) {
        out += (i == 0 ? "\n    " : ",\n    ") + quoted(result.notes[i]);
    }
    out += result.notes.empty() ? "]\n" : "\n  ]\n";
    out += "}\n";
    return out;
}

} // namespace hookscan
