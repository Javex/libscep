find_package(Check REQUIRED)
include_directories(${CHECK_INCLUDE_DIRS})
set (CHECK_LIBRARIES scep ${CHECK_LIBRARIES})
set (CFLAGS "-g -O0 -Wall -W -fprofile-arcs -ftest-coverage ${CFLAGS}")
set (LDFLAGS "-fprofile-arcs -ftest-coverage ${LDFLAGS}")

file (COPY test-files DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
add_custom_target(build_test)
set (SUBMODULES ${CMAKE_CURRENT_SOURCE_DIR}/submodules)
set (SUBMODULE_PREFIX ${PROJECT_BINARY_DIR}/prefix)
set (LOG_DIR ${PROJECT_BINARY_DIR}/logs)
file(MAKE_DIRECTORY ${SUBMODULE_PREFIX})
file(MAKE_DIRECTORY ${LOG_DIR})
file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/tmp)
include_directories(${PROJECT_BINARY_DIR}/prefix/include)

# If we don't have botan, we build it here
find_library(LIBBOTAN botan ${SUBMODULE_PREFIX}/lib)
if(NOT LIBBOTAN)
    set (BOTAN_DIR ${SUBMODULES}/botan)
    message( "Building libbotan dependency" )
    execute_process(
        COMMAND git submodule update ${SUBMODULES}/botan
        OUTPUT_QUIET)
    execute_process(
        COMMAND python2 configure.py --prefix ${SUBMODULE_PREFIX}
        OUTPUT_FILE ${LOG_DIR}/botan_configure_stdout.log
        ERROR_FILE ${LOG_DIR}/botan_configure_stderr.log
        WORKING_DIRECTORY ${BOTAN_DIR})
    execute_process(
        COMMAND make
        OUTPUT_FILE ${LOG_DIR}/botan_make_stdout.log
        ERROR_FILE ${LOG_DIR}/botan_make_stderr.log
        WORKING_DIRECTORY ${BOTAN_DIR})
    execute_process(
        COMMAND make install
        OUTPUT_FILE ${LOG_DIR}/botan_make_install_stdout.log
        ERROR_FILE ${LOG_DIR}/botan_make_install_stderr.log
        WORKING_DIRECTORY ${BOTAN_DIR})
    find_library(LIBBOTAN botan  ${SUBMODULE_PREFIX}/lib)
endif()

# Same for SoftHSM
find_library(LIBSOFTHSM softhsm ${SUBMODULE_PREFIX}/lib/softhsm)
if(NOT LIBSOFTHSM)
    set (SOFTHSM_DIR ${SUBMODULES}/SoftHSMv1)
    message( "Building libsofthsm dependency" )
    execute_process(
        COMMAND git submodule update ${SUBMODULES}/SoftHSMv1
        OUTPUT_QUIET)
    execute_process(
        COMMAND sh autogen.sh
        WORKING_DIRECTORY ${SOFTHSM_DIR}
        OUTPUT_FILE ${LOG_DIR}/softhsm_autogen_stdout.log
        ERROR_FILE ${LOG_DIR}/softhsm_autogen_stderr.log)
    execute_process(
        COMMAND ./configure --with-botan=${SUBMODULE_PREFIX} --prefix=${SUBMODULE_PREFIX}
        WORKING_DIRECTORY ${SOFTHSM_DIR}
        OUTPUT_FILE ${LOG_DIR}/softhsm_configure_stdout.log
        ERROR_FILE ${LOG_DIR}/softhsm_configure_stderr.log)
    execute_process(
        COMMAND make
        WORKING_DIRECTORY ${SOFTHSM_DIR}
        OUTPUT_FILE ${LOG_DIR}/softhsm_make_stdout.log
        ERROR_FILE ${LOG_DIR}/softhsm_make_stderr.log)
    execute_process(
        COMMAND make install
        WORKING_DIRECTORY ${SOFTHSM_DIR}
        OUTPUT_FILE ${LOG_DIR}/softhsm_make_install_stdout.log
        ERROR_FILE ${LOG_DIR}/softhsm_make_install_stderr.log)
    find_library(LIBSOFTHSM softhsm ${SUBMODULE_PREFIX}/lib/softhsm)
endif()
set (CHECK_LIBRARIES ${LIBBOTAN} ${LIBSOFTHSM} ${CHECK_LIBRARIES})

# Now we need to find the engine_pkcs11
find_file(ENGINE_PKCS11 engine_pkcs11.so ${SUBMODULE_PREFIX}/lib/engines /usr/lib/engines)
if(NOT ENGINE_PKCS11)
    # We need libp11, so if that's not present we need to install it first
    find_library(LIBP11 p11 ${SUBMODULE_PREFIX}/lib)
    if(NOT LIBP11)
        message ( "Building libp11" )
    execute_process(
        COMMAND git submodule update ${SUBMODULES}/libp11
        OUTPUT_QUIET)
        execute_process(
            COMMAND ./bootstrap
            OUTPUT_FILE ${LOG_DIR}/libp11_bootstrap_stdout.log
            ERROR_FILE ${LOG_DIR}/libp11_bootstrap_stderr.log
            WORKING_DIRECTORY ${SUBMODULES}/libp11)
        execute_process(
            COMMAND ./configure --prefix=${SUBMODULE_PREFIX}
            OUTPUT_FILE ${LOG_DIR}/libp11_configure_stdout.log
            ERROR_FILE ${LOG_DIR}/libp11_configure_stderr.log
            WORKING_DIRECTORY ${SUBMODULES}/libp11)
        execute_process(
            COMMAND make
            OUTPUT_FILE ${LOG_DIR}/libp11_make_stdout.log
            ERROR_FILE ${LOG_DIR}/libp11_make_stderr.log
            WORKING_DIRECTORY ${SUBMODULES}/libp11)
        execute_process(
            COMMAND make install
            OUTPUT_FILE ${LOG_DIR}/libp11_make_install_stdout.log
            ERROR_FILE ${LOG_DIR}/libp11_make_install_stderr.log
            WORKING_DIRECTORY ${SUBMODULES}/libp11)
    endif()
    find_library(LIBP11 p11 ${SUBMODULE_PREFIX}/lib)
    if(NOT LIBP11)
        message( FATAL_ERROR "libp11 could neither be found nor be built from source. Cannot build engine and thus tests!" )
    endif()
    set (ENGINE_DIR ${SUBMODULES}/engine_pkcs11)
    message( "Building engine_pkcs11" )
    execute_process(
        COMMAND git submodule update ${SUBMODULES}/engine_pkcs11
        OUTPUT_QUIET)
    execute_process(
        COMMAND ./bootstrap
        WORKING_DIRECTORY ${SUBMODULES}/engine_pkcs11
        OUTPUT_FILE ${LOG_DIR}/engine_pkcs11_bootstrap_stdout.log
        ERROR_FILE ${LOG_DIR}/engine_pkcs11_bootstrap_stderr.log)
    execute_process(
        COMMAND ./configure PKG_CONFIG_PATH=${SUBMODULE_PREFIX}/lib/pkgconfig --prefix=${SUBMODULE_PREFIX}
        WORKING_DIRECTORY ${SUBMODULES}/engine_pkcs11
        OUTPUT_FILE ${LOG_DIR}/engine_pkcs11_configure_stdout.log
        ERROR_FILE ${LOG_DIR}/engine_pkcs11_configure_stderr.log)
    execute_process(
        COMMAND make
        WORKING_DIRECTORY ${SUBMODULES}/engine_pkcs11
        OUTPUT_FILE ${LOG_DIR}/engine_pkcs11_make_stdout.log
        ERROR_FILE ${LOG_DIR}/engine_pkcs11_make_stderr.log)
    execute_process(
        COMMAND make install
        WORKING_DIRECTORY ${SUBMODULES}/engine_pkcs11
        OUTPUT_FILE ${LOG_DIR}/engine_pkcs11_make_install_stdout.log
        ERROR_FILE ${LOG_DIR}/engine_pkcs11_make_install_stderr.log)
    find_file(ENGINE_PKCS11 engine_pkcs11.so ${SUBMODULE_PREFIX}/lib/engines /usr/lib/engines)
endif()

if(NOT ENGINE_PKCS11)
    message( FATAL_ERROR "engine_pkcs11 was not found and could not be built. Cannot build tests!" )
endif()

# Set the variables to be filled in the header
set (MODULE_PATH ${LIBSOFTHSM})
set (ENGINE_PATH ${ENGINE_PKCS11})
# If botan is not found by default, we need to tell the tests to include
# the correct LD_LIBRARY_PATH
find_library(BOTAN_DEFAULT botan)
if(NOT BOTAN_DEFAULT)
    set (BOTAN_LIB_PATH "\"${SUBMODULE_PREFIX}/lib\"")
    set (ENV{LD_LIBRARY_PATH} ${BOTAN_LIB_PATH})
else()
    set (BOTAN_LIB_PATH NULL)
endif()

# Now prepare the files unit tests need to run
execute_process(
    COMMAND echo 0:softhsm-slot0.db
    OUTPUT_FILE "${PROJECT_BINARY_DIR}/softhsm.conf")
execute_process(
    COMMAND openssl genrsa -out ${PROJECT_BINARY_DIR}/tmp/some_key.pem
    ERROR_QUIET)
execute_process(
    COMMAND openssl pkcs8 -topk8 -in ${PROJECT_BINARY_DIR}/tmp/some_key.pem -out ${PROJECT_BINARY_DIR}/tmp/some_key.p8 -nocrypt)
find_program(SOFTHSM_BIN softhsm ${SUBMODULE_PREFIX}/bin)
if(NOT SOFTHSM_BIN)
    message( FATAL_ERROR "Could not find softhsm executable" )
endif()

# Now we need to put our dynamic settings in the header for tests
configure_file (
    "${CMAKE_CURRENT_SOURCE_DIR}/scep_tests.h.in"
    "${PROJECT_BINARY_DIR}/scep_tests.h"
    )

# Dirty hack because somehow softhsm does not directly accept our environemt
# variables, though env reports LD_LIBRARY_PATH correctly... So we write a
# script, execute that and delete it afterwards.
file(WRITE
    ${PROJECT_BINARY_DIR}/token_setup.sh
    "export LD_LIBRARY_PATH=$ENV{LD_LIBRARY_PATH} && export SOFTHSM_CONF=softhsm.conf && ${SOFTHSM_BIN} --init-token --slot 0 --label foo --pin 1234 --so-pin 123456 && ${SOFTHSM_BIN} --import ${PROJECT_BINARY_DIR}/tmp/some_key.p8 --slot 0 --pin 1234 --label foo --id 01")
execute_process(COMMAND sh ${PROJECT_BINARY_DIR}/token_setup.sh
    OUTPUT_QUIET)
file(REMOVE ${PROJECT_BINARY_DIR}/token_setup.sh)

# Unit tests
foreach (target ${TEST_TARGETS})
    add_executable(test_${target} EXCLUDE_FROM_ALL test_${target}.c)
    add_dependencies(build_test test_${target})
    target_link_libraries(test_${target} ${CHECK_LIBRARIES})
endforeach (target)
add_executable(test_message EXCLUDE_FROM_ALL test_message.c test_message_pkcsreq.c test_message_get_cert_initial.c test_message_get_cert.c test_message_get_crl.c test_message_certrep.c test_message_helper.c)
add_dependencies(build_test test_message)
target_link_libraries(test_message ${CHECK_LIBRARIES})