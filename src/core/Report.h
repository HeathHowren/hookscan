#pragma once

#include "core/Scanner.h"

#include <string>
#include <string_view>

namespace hookscan {

// The readable report: one block per finding, then notes, then a count.
[[nodiscard]] std::string formatText(const ScanResult& result, bool showNotes);

// One JSON object. Addresses are hex strings, since a 64-bit address does not
// survive a JSON number in most parsers.
[[nodiscard]] std::string formatJson(const ScanResult& result);

[[nodiscard]] std::string jsonEscape(std::string_view text);

} // namespace hookscan
