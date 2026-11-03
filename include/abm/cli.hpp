// abm command-line interface.
#pragma once

#include <iosfwd>
#include <string>
#include <vector>

namespace abm::cli {

// Run the CLI with argv (excluding the program name). Returns the process exit code.
int run(const std::vector<std::string>& args, std::ostream& out, std::ostream& err);

}  // namespace abm::cli
