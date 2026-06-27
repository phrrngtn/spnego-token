cmake_minimum_required(VERSION 3.15...3.30)
project(spnego_token LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# This CMake builds the *Python* (nanobind) module via scikit-build-core (pip/uv).
# To use the C++ atom standalone, you do NOT need this file: just add the repo as a
# submodule, include its directory, and compile spnego_token.cpp into your target.

find_package(Python 3.9 COMPONENTS Interpreter Development.Module REQUIRED)

execute_process(
  COMMAND "${Python_EXECUTABLE}" -m nanobind --cmake_dir
  OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE nanobind_ROOT)
list(APPEND CMAKE_PREFIX_PATH "${nanobind_ROOT}")
find_package(nanobind CONFIG REQUIRED)

nanobind_add_module(spnego_token NB_STATIC
  spnego_token.cpp
  python/bindings.cpp)
target_include_directories(spnego_token PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/json/single_include)  # nlohmann::json (submodule)

# macOS/Linux dlopen GSS at runtime (no link dep). Windows SSPI lives in secur32.
if(WIN32)
  target_link_libraries(spnego_token PRIVATE secur32)
endif()

install(TARGETS spnego_token LIBRARY DESTINATION .)
