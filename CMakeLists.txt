cmake_minimum_required(VERSION 3.16)
project(LoginGuard VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(LG_BUILD_TESTS "Build the unit / integration tests" ON)
option(LG_FORCE_VENDORED_SQLITE "Always compile the bundled SQLite instead of using a system copy" OFF)

find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# SQLite: use the system library when available, otherwise the bundled amalgamation
# (so a plain `cmake -B build && cmake --build build` works on Windows/macOS/Linux).
# ---------------------------------------------------------------------------
set(LG_SQLITE_TARGET "")
if(NOT LG_FORCE_VENDORED_SQLITE)
  find_package(SQLite3 QUIET)
  if(SQLite3_FOUND)
    set(LG_SQLITE_TARGET SQLite::SQLite3)
    message(STATUS "LoginGuard: using system SQLite ${SQLite3_VERSION}")
  endif()
endif()
if(NOT LG_SQLITE_TARGET)
  message(STATUS "LoginGuard: building bundled SQLite")
  add_library(lg_sqlite STATIC third_party/sqlite3/sqlite3.c)
  target_include_directories(lg_sqlite SYSTEM PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/third_party/sqlite3)
  target_compile_definitions(lg_sqlite PRIVATE SQLITE_THREADSAFE=1 SQLITE_OMIT_LOAD_EXTENSION=1)
  target_link_libraries(lg_sqlite PUBLIC Threads::Threads)
  set_target_properties(lg_sqlite PROPERTIES C_STANDARD 11 POSITION_INDEPENDENT_CODE ON)
  if(NOT MSVC)
    target_compile_options(lg_sqlite PRIVATE -w)
  endif()
  set(LG_SQLITE_TARGET lg_sqlite)
endif()

# ---------------------------------------------------------------------------
# Core library: everything except main()
# ---------------------------------------------------------------------------
add_library(loginguard_core STATIC
  src/util.cpp
  src/config.cpp
  src/parser.cpp
  src/detector.cpp
  src/scorer.cpp
  src/analysis.cpp
  src/loggen.cpp
  src/evaluate.cpp
  src/storage.cpp
  src/api.cpp)
target_include_directories(loginguard_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(loginguard_core SYSTEM PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/third_party)
target_link_libraries(loginguard_core PUBLIC ${LG_SQLITE_TARGET} Threads::Threads)
if(WIN32)
  target_link_libraries(loginguard_core PUBLIC ws2_32)
  target_compile_definitions(loginguard_core PUBLIC _WIN32_WINNT=0x0A00 NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
endif()
if(MSVC)
  target_compile_options(loginguard_core PUBLIC /W4 /utf-8 /bigobj)
else()
  target_compile_options(loginguard_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ---------------------------------------------------------------------------
# Executable
# ---------------------------------------------------------------------------
add_executable(loginguard src/main.cpp)
target_link_libraries(loginguard PRIVATE loginguard_core)
target_compile_definitions(loginguard PRIVATE LG_VERSION="${PROJECT_VERSION}")

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(LG_BUILD_TESTS)
  enable_testing()
  add_executable(loginguard_tests tests/test_main.cpp)
  target_link_libraries(loginguard_tests PRIVATE loginguard_core)
  add_test(NAME loginguard_tests COMMAND loginguard_tests)
endif()
