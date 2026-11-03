#include "abm/cli.hpp"

#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

int main(int argc, char** argv) {
#ifdef _WIN32
  SetConsoleOutputCP(CP_UTF8);
#endif
  std::vector<std::string> args(argv + 1, argv + argc);
  return abm::cli::run(args, std::cout, std::cerr);
}
