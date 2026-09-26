#include "core/ApiSet.h"

#include "core/PeImage.h"

#include <windows.h>
#include <winternl.h>

#include <cstring>

namespace hookscan {

namespace {

std::optional<std::uint32_t> u32(std::span<const std::uint8_t> bytes, std::uint64_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 4) {
        return std::nullopt;
    }
    std::uint32_t v;
    std::memcpy(&v, bytes.data() + offset, 4);
    return v;
}

// Schema strings are UTF-16 with no terminator. API set and DLL names are
// ASCII, so anything else is dropped rather than converted.
std::string narrow(std::span<const std::uint8_t> bytes, std::uint64_t offset, std::uint32_t lengthBytes) {
    std::string out;
    if (offset > bytes.size() || bytes.size() - offset < lengthBytes) {
        return out;
    }
    for (std::uint32_t i = 0; i + 1 < lengthBytes; i += 2) {
        const auto at = static_cast<std::size_t>(offset + i);
        const auto c = static_cast<std::uint16_t>(bytes[at] | (bytes[at + 1] << 8));
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
        }
    }
    return toLower(out);
}

// "api-ms-win-core-synch-l1-2-0.dll" -> "api-ms-win-core-synch-l1-2"
std::string lookupKey(std::string_view dll) {
    std::string name = toLower(dll);
    if (name.size() > 4 && name.ends_with(".dll")) {
        name.resize(name.size() - 4);
    }
    const auto dash = name.rfind('-');
    if (dash != std::string::npos) {
        name.resize(dash);
    }
    return name;
}

} // namespace

ApiSetResolver ApiSetResolver::fromSchema(std::span<const std::uint8_t> schema) {
    ApiSetResolver resolver;
    const auto version = u32(schema, 0);
    const auto count = u32(schema, 12);
    const auto entryOffset = u32(schema, 16);
    if (!version || *version != 6 || !count || !entryOffset || *count > 0x10000) {
        return resolver;
    }
    for (std::uint32_t i = 0; i < *count; ++i) {
        const std::uint64_t entry = static_cast<std::uint64_t>(*entryOffset) + i * 24ull;
        const auto nameOffset = u32(schema, entry + 4);
        const auto hashedLength = u32(schema, entry + 12);
        const auto valueOffset = u32(schema, entry + 16);
        const auto valueCount = u32(schema, entry + 20);
        if (!nameOffset || !hashedLength || !valueOffset || !valueCount || *valueCount > 0x100) {
            break;
        }
        Host host;
        for (std::uint32_t v = 0; v < *valueCount; ++v) {
            const std::uint64_t value = *valueOffset + v * 20ull;
            const auto importerOffset = u32(schema, value + 4);
            const auto importerLength = u32(schema, value + 8);
            const auto hostOffset = u32(schema, value + 12);
            const auto hostLength = u32(schema, value + 16);
            if (!importerOffset || !importerLength || !hostOffset || !hostLength) {
                break;
            }
            std::string hostName = narrow(schema, *hostOffset, *hostLength);
            if (*importerLength == 0) {
                host.defaultHost = std::move(hostName);
            } else {
                host.exceptions[narrow(schema, *importerOffset, *importerLength)] = std::move(hostName);
            }
        }
        resolver.sets_[narrow(schema, *nameOffset, *hashedLength)] = std::move(host);
    }
    return resolver;
}

const ApiSetResolver& ApiSetResolver::system() {
    static const ApiSetResolver resolver = [] {
        const auto* peb = reinterpret_cast<const std::uint8_t*>(NtCurrentTeb()->ProcessEnvironmentBlock);
#if defined(_WIN64)
        constexpr std::size_t kApiSetMapOffset = 0x68;
#else
        constexpr std::size_t kApiSetMapOffset = 0x38;
#endif
        const std::uint8_t* map = nullptr;
        std::memcpy(&map, peb + kApiSetMapOffset, sizeof(map));
        if (map == nullptr) {
            return ApiSetResolver{};
        }
        std::uint32_t size = 0;
        std::memcpy(&size, map + 4, sizeof(size));
        if (size < 28 || size > 0x1000000) {
            return ApiSetResolver{};
        }
        return fromSchema(std::span<const std::uint8_t>(map, size));
    }();
    return resolver;
}

bool ApiSetResolver::isApiSetName(std::string_view dll) {
    const std::string lower = toLower(dll.substr(0, 4));
    return lower == "api-" || lower == "ext-";
}

std::optional<std::string> ApiSetResolver::resolve(std::string_view dll, std::string_view importingModule) const {
    if (!isApiSetName(dll)) {
        return std::nullopt;
    }
    const auto it = sets_.find(lookupKey(dll));
    if (it == sets_.end()) {
        return std::nullopt;
    }
    const Host& host = it->second;
    if (!importingModule.empty()) {
        const auto exception = host.exceptions.find(toLower(importingModule));
        if (exception != host.exceptions.end()) {
            return exception->second;
        }
    }
    return host.defaultHost;
}

} // namespace hookscan
