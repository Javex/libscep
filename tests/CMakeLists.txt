include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src)

find_package(Check REQUIRED)
include_directories(${CHECK_INCLUDE_DIRS})

set (CHECK_LIBRARIES curl crypto scep ${CHECK_LIBRARIES})
set (CFLAGS "-g -O0 -Wall -W -fprofile-arcs -ftest-coverage ${CFLAGS}")
set (LDFLAGS "-fprofile-arcs -ftest-coverage ${LDFLAGS}")

file (COPY test-files DESTINATION ${CMAKE_CURRENT_BINARY_DIR})


# Unit tests
foreach (target ${TEST_TARGETS})
    add_executable(test_${target} test_${target}.c)
    target_link_libraries(test_${target} ${CHECK_LIBRARIES})
endforeach (target)