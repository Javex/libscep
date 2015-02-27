cmake_minimum_required (VERSION 2.8 FATAL_ERROR)
project (libscep C)

set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

###############################################################################
include (CheckCSourceCompiles)
include (CheckCSourceRuns)
include (CheckFunctionExists)
include (CheckIncludeFile)
include (CheckIncludeFiles)
include (CheckLibraryExists)
include (CheckSymbolExists)
include (CheckTypeSize)

# Version
set (libscep_VERSION_MAJOR 0)
set (libscep_VERSION_MINOR 0)


configure_file (
    "${PROJECT_SOURCE_DIR}/src/scep.h.in"
    "${PROJECT_BINARY_DIR}/scep.h"
    )

include_directories ("${PROJECT_BINARY_DIR}")
add_subdirectory (src)

# Unit tests
set (TEST_TARGETS configuration util scep operation message)
add_subdirectory (tests)
enable_testing ()
foreach (target ${TEST_TARGETS})
    add_test (NAME test_${target} COMMAND test_${target})
endforeach (target)