include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src)

find_package(Check REQUIRED)
include_directories(${CHECK_INCLUDE_DIRS})
set (CHECK_LIBRARIES scep ${CHECK_LIBRARIES})
set (CFLAGS "-g -O0 -Wall -W -fprofile-arcs -ftest-coverage ${CFLAGS}")
set (LDFLAGS "-fprofile-arcs -ftest-coverage ${LDFLAGS}")

file (COPY test-files DESTINATION ${CMAKE_CURRENT_BINARY_DIR})


# Unit tests
add_custom_target(build_test)
foreach (target ${TEST_TARGETS})
    add_executable(test_${target} EXCLUDE_FROM_ALL test_${target}.c)
    add_dependencies(build_test test_${target})
    target_link_libraries(test_${target} ${CHECK_LIBRARIES})
endforeach (target)
add_executable(test_message EXCLUDE_FROM_ALL test_message.c test_message_pkcsreq.c test_message_get_cert_initial.c test_message_get_cert.c test_message_get_crl.c test_message_certrep.c test_message_helper.c)
add_dependencies(build_test test_message)
target_link_libraries(test_message ${CHECK_LIBRARIES})