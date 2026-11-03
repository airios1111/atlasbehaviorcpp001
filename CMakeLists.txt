cmake_minimum_required(VERSION 3.20)
project(atlas_behavior_map VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(ABM_BUILD_TESTS "Build the doctest unit/integration tests" ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

include(cmake/Dependencies.cmake)

# ------------------------------------------------------------------ library
add_library(abm_core STATIC
  src/util/pyfmt.cpp
  src/util/regex.cpp
  src/util/hash.cpp
  src/util/timeutil.cpp
  src/util/yaml.cpp
  src/util/http.cpp
  src/util/pyrandom.cpp
  src/models.cpp
  src/catalog.cpp
  src/loader.cpp
  src/response.cpp
  src/engine.cpp
  src/validator.cpp
  src/coverage.cpp
  src/compilers/common.cpp
  src/compilers/kql.cpp
  src/compilers/sigma.cpp
  src/compilers/spl.cpp
  src/cli.cpp
)
target_include_directories(abm_core PUBLIC include)
target_compile_definitions(abm_core PUBLIC ABM_VERSION="${PROJECT_VERSION}")
target_link_libraries(abm_core PUBLIC
  yaml-cpp::yaml-cpp
  nlohmann_json::nlohmann_json
  CLI11::CLI11
  ${ABM_PCRE2_TARGET}
)
target_compile_definitions(abm_core PUBLIC PCRE2_CODE_UNIT_WIDTH=8 PCRE2_STATIC)

if(WIN32)
  target_link_libraries(abm_core PRIVATE winhttp)
  target_compile_definitions(abm_core PRIVATE ABM_HTTP_WINHTTP NOMINMAX WIN32_LEAN_AND_MEAN)
else()
  find_package(CURL)
  if(CURL_FOUND)
    target_link_libraries(abm_core PRIVATE CURL::libcurl)
    target_compile_definitions(abm_core PRIVATE ABM_HTTP_CURL)
  else()
    message(WARNING "libcurl not found: webhook / XSOAR / atlas-sync downloads will be unavailable")
  endif()
endif()

if(MSVC)
  target_compile_options(abm_core PUBLIC /utf-8 /W4 /permissive- /Zc:__cplusplus)
else()
  target_compile_options(abm_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ------------------------------------------------------------------ cli
add_executable(abm src/main.cpp)
target_link_libraries(abm PRIVATE abm_core)
if(MINGW)
  # self-contained exe: no dependency on the MinGW runtime DLLs being on PATH
  target_link_options(abm PRIVATE -static)
endif()
# deterministic fixture generator (port of scripts/gen_fixtures.py + examples/tutorial/gen_fixtures.py)
add_executable(gen_fixtures tools/gen_fixtures.cpp)
target_link_libraries(gen_fixtures PRIVATE abm_core)
if(MINGW)
  target_link_options(gen_fixtures PRIVATE -static)
endif()

install(TARGETS abm RUNTIME DESTINATION bin)

# ------------------------------------------------------------------ tests
if(ABM_BUILD_TESTS)
  enable_testing()
  add_executable(abm_tests
    tests/test_main.cpp
    tests/test_models.cpp
    tests/test_engine.cpp
    tests/test_compilers_coverage.cpp
    tests/test_tutorial.cpp
    tests/test_xsoar.cpp
    tests/test_pyfmt.cpp
  )
  target_link_libraries(abm_tests PRIVATE abm_core doctest::doctest)
  target_compile_definitions(abm_tests PRIVATE ABM_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
  if(MINGW)
    target_link_options(abm_tests PRIVATE -static)
  endif()
  add_test(NAME unit COMMAND abm_tests)
  add_test(NAME validate-run-tests
           COMMAND abm --root ${CMAKE_CURRENT_SOURCE_DIR} validate --run-tests -q)
endif()
