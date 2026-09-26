include(FetchContent)

FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.5.2
    EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(Catch2)

# The fixture: a small exe that changes its own code and tables in known ways
# (by hand, with VirtualProtect and memcpy) and then waits, so the tests can
# scan it. Incremental linking is off, or &function would be an ILT thunk
# rather than the function, and the patch would land on the thunk.
add_executable(hookscan_fixture fixture/fixture.cpp)
target_link_libraries(hookscan_fixture PRIVATE hookscan_warnings)
target_compile_definitions(hookscan_fixture PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_options(hookscan_fixture PRIVATE /INCREMENTAL:NO)

add_executable(hookscan_tests
    test_apiset.cpp
    test_cli.cpp
    test_disasm.cpp
    test_diff.cpp
    test_live.cpp
    test_pe.cpp
    test_relocations.cpp
    test_report.cpp
)
target_include_directories(hookscan_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(hookscan_tests PRIVATE hookscan_core hookscan_warnings Catch2::Catch2WithMain)
target_compile_definitions(hookscan_tests PRIVATE
    HOOKSCAN_FIXTURE_EXE="$<TARGET_FILE:hookscan_fixture>"
    HOOKSCAN_CLI_EXE="$<TARGET_FILE:hookscan_cli>"
)
add_dependencies(hookscan_tests hookscan_fixture hookscan_cli)

list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(Catch)
catch_discover_tests(hookscan_tests)
