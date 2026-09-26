# 3.28 for EXCLUDE_FROM_ALL in FetchContent_Declare, which keeps Zydis's own
# tools and tests out of the default build.
cmake_minimum_required(VERSION 3.28)

project(hookscan VERSION 1.0.0 LANGUAGES C CXX)

if(NOT MSVC)
    message(FATAL_ERROR "hookscan reads Windows processes and builds with MSVC only.")
endif()

get_property(_hs_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(NOT _hs_multi_config AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Static CRT, so hookscan.exe runs on a clean Windows with no VC++ redistributable.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

option(HOOKSCAN_BUILD_TESTS "Build the unit tests and the test fixture" ON)
option(HOOKSCAN_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(HOOKSCAN_ARCH x64)
else()
    set(HOOKSCAN_ARCH x86)
endif()

include(FetchContent)

# ---------------------------------------------------------------------------
# Dependencies, pinned (see THIRD_PARTY_NOTICES.md)
# ---------------------------------------------------------------------------

# Zydis: the x86/x64 decoder (MIT). The same commit Pointer Lab and Signature
# Lab pin, so the three tools disassemble identically.
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES   OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TOOLS      OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN    OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_MAN        OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS      OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG a2278f1d254e492f6a6b39f6cb5d1f5d515659dc # v4.1.1
    EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(zydis)

# ---------------------------------------------------------------------------
# Warnings, first-party targets only
# ---------------------------------------------------------------------------

add_library(hookscan_warnings INTERFACE)
# /w44062: a switch over an enum that misses an enumerator is an error, so a
# new finding kind cannot be silently dropped by the report writers.
target_compile_options(hookscan_warnings INTERFACE /W4 /w44062 /permissive- /Zc:__cplusplus /utf-8)
if(HOOKSCAN_WARNINGS_AS_ERRORS)
    target_compile_options(hookscan_warnings INTERFACE /WX)
endif()

# ---------------------------------------------------------------------------
# hookscan_core: the PE model, relocations, the diff, the decoder and the
# scanner. The CLI is a thin layer over it, and the tests link it directly.
# ---------------------------------------------------------------------------

add_library(hookscan_core STATIC
    src/core/ApiSet.cpp
    src/core/Diff.cpp
    src/core/Disasm.cpp
    src/core/PeImage.cpp
    src/core/Process.cpp
    src/core/Relocations.cpp
    src/core/Report.cpp
    src/core/Scanner.cpp
)
target_compile_features(hookscan_core PUBLIC cxx_std_20)
target_include_directories(hookscan_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(hookscan_core PUBLIC
    WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE
    HOOKSCAN_VERSION="${PROJECT_VERSION}"
)
target_link_libraries(hookscan_core PUBLIC Zydis PRIVATE hookscan_warnings)

# ---------------------------------------------------------------------------
# The CLI: hookscan.exe
# ---------------------------------------------------------------------------

add_executable(hookscan_cli src/cli/main.cpp)
set_target_properties(hookscan_cli PROPERTIES OUTPUT_NAME hookscan)
target_link_libraries(hookscan_cli PRIVATE hookscan_core hookscan_warnings)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if(HOOKSCAN_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Package: a zip with the tool and the notices.
# ---------------------------------------------------------------------------

install(TARGETS hookscan_cli RUNTIME DESTINATION .)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE
    ${CMAKE_CURRENT_SOURCE_DIR}/README.md
    ${CMAKE_CURRENT_SOURCE_DIR}/CHANGELOG.md
    ${CMAKE_CURRENT_SOURCE_DIR}/THIRD_PARTY_NOTICES.md
    DESTINATION .
)

set(CPACK_PACKAGE_NAME "hookscan")
set(CPACK_PACKAGE_VENDOR "Game Reversal Club")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "hookscan-v${PROJECT_VERSION}-windows-${HOOKSCAN_ARCH}")
set(CPACK_GENERATOR "ZIP")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Read-only scanner for modified code, IAT and EAT entries in a running process")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
include(CPack)
