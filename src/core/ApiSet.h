#pragma once

#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace hookscan {

// Resolves API set names ("api-ms-win-core-synch-l1-2-0.dll") to the DLL
// that implements them, the way the loader does. Windows 10 and 11 use
// schema version 6; any other version leaves the resolver empty, and every
// lookup then reports "not resolved" rather than guessing.
class ApiSetResolver {
public:
    struct Host {
        std::string defaultHost;                       // lower case, "" when the set has no host on this system
        std::map<std::string, std::string> exceptions; // importing module (lower case) -> host
    };

    ApiSetResolver() = default;

    // Parses a version 6 schema from its bytes (the PEB's ApiSetMap).
    [[nodiscard]] static ApiSetResolver fromSchema(std::span<const std::uint8_t> schema);

    // The schema this process was started with. It is the same map every
    // process on the system gets, so it answers for the target too.
    [[nodiscard]] static const ApiSetResolver& system();

    [[nodiscard]] static bool isApiSetName(std::string_view dll);

    // The host DLL for `dll` as imported by `importingModule`, lower case with
    // ".dll". std::nullopt when `dll` is not an API set name or the set is
    // unknown; an empty string when the set exists but has no host here.
    [[nodiscard]] std::optional<std::string> resolve(std::string_view dll, std::string_view importingModule) const;

    [[nodiscard]] bool empty() const { return sets_.empty(); }
    [[nodiscard]] std::size_t size() const { return sets_.size(); }

private:
    std::map<std::string, Host, std::less<>> sets_; // keyed by the name without its last "-N" component
};

} // namespace hookscan
