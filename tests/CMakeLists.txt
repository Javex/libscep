find_package(Check REQUIRED)
include_directories(${CHECK_INCLUDE_DIRS})
set (CHECK_LIBRARIES scep ${CHECK_LIBRARIES})
set (CFLAGS "-g -O0 -Wall -W -fprofile-arcs -ftest-coverage ${CFLAGS}")
set (LDFLAGS "-fprofile-arcs -ftest-coverage ${LDFLAGS}")

file (COPY test-files DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
add_custom_target(build_test)

if(WITH_ENGINE_TESTS)
    add_definitions(-DWITH_ENGINE_TESTS)
    set (SUBMODULES ${CMAKE_CURRENT_SOURCE_DIR}/submodules)
    set (SUBMODULE_PREFIX ${PROJECT_BINARY_DIR}/prefix)
    set (LOG_DIR ${PROJECT_BINARY_DIR}/logs)
    set (SCRIPTS ${CMAKE_CURRENT_SOURCE_DIR}/scripts)
    file(MAKE_DIRECTORY ${SUBMODULE_PREFIX})
    file(MAKE_DIRECTORY ${LOG_DIR})
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/tmp)
    include_directories(${PROJECT_BINARY_DIR}/prefix/include)
    check_include_files("openssl/engine.h" ENGINE_ENABLED)
    if(NOT ENGINE_ENABLED)
        message( FATAL_ERROR "OpenSSL has no engine support! Cannot run engine tests. Build with -DWITH_ENGINE_TESTS=no.")
    endif()
    # Same for SoftHSM
    set (OLD_CFLAGS ENV{$CFLAGS})
    set (ENV{CFLAGS} "")
    find_library(LIBSOFTHSM softhsm ${SUBMODULE_PREFIX}/lib/softhsm)
    if(NOT LIBSOFTHSM)

        # botan is required for SoftHSM, we need to build it here
        find_library(LIBBOTAN botan ${SUBMODULE_PREFIX}/lib)
        if(NOT LIBBOTAN)
            message( "Building libbotan dependency" )
            execute_process(
                COMMAND sh -e ${SCRIPTS}/build_botan.sh "${SUBMODULE_PREFIX}"
                WORKING_DIRECTORY ${SUBMODULES}
                OUTPUT_FILE ${LOG_DIR}/botan.log)
            find_library(LIBBOTAN botan  ${SUBMODULE_PREFIX}/lib)
        endif()

        if(NOT LIBBOTAN)
            message( FATAL_ERROR "Unable to find or build libbotan")
        endif()

        # Check if we have botan in our default search path. Otherwise, we
        # need to pass an explicit prefix for it
        find_library(BOTAN_NATIVE p11)
        if(BOTAN_NATIVE)
            set (BOTAN_PREFIX "")
        else()
            set (BOTAN_PREFIX "${SUBMODULE_PREFIX}")
        endif()

        message( "Building libsofthsm dependency" )
        execute_process(
            COMMAND sh -e ${SCRIPTS}/build_softhsm.sh "${SUBMODULE_PREFIX}" "${BOTAN_PREFIX}"
            WORKING_DIRECTORY ${SUBMODULES}
                OUTPUT_FILE ${LOG_DIR}/softhsm.log)
        find_library(LIBSOFTHSM softhsm ${SUBMODULE_PREFIX}/lib/softhsm)
    endif()
    if(NOT LIBSOFTHSM)
        message( FATAL_ERROR "Unable to find or build SoftHSMv1")
    endif()

    # Now we need to find the engine_pkcs11
    find_file(ENGINE_PKCS11 engine_pkcs11.so ${SUBMODULE_PREFIX}/lib/engines /usr/lib/engines)
    if(NOT ENGINE_PKCS11)
        # We need libp11, so if that's not present we need to install it first
        find_library(LIBP11 p11 ${SUBMODULE_PREFIX}/lib)
        if(NOT LIBP11)
            message ( "Building libp11" )
            execute_process(
                COMMAND sh -e ${SCRIPTS}/build_libp11.sh "${SUBMODULE_PREFIX}"
                WORKING_DIRECTORY ${SUBMODULES}
                    OUTPUT_FILE ${LOG_DIR}/libp11.log)
        endif()

        # Check if we have the library in our default search path. Otherwise, we
        # need to pass the PKG_CONFIG_PATH variable to find it
        find_library(LIBP11_NATIVE p11)
        if(LIBP11_NATIVE)
            set (PKGCFG "")
        else()
            set (PKGCFG "${SUBMODULE_PREFIX}/lib/pkgconfig")
        endif()

        # Build libp11 if we don't have it
        find_library(LIBP11 p11 ${SUBMODULE_PREFIX}/lib)
        if(NOT LIBP11)
            message( FATAL_ERROR "libp11 could neither be found nor be built from source. Cannot build engine and thus tests!" )
        endif()
        set (ENGINE_DIR ${SUBMODULES}/engine_pkcs11)
        message( "Building engine_pkcs11" )
        execute_process(
            COMMAND sh -e ${SCRIPTS}/build_engine_pkcs11.sh "${SUBMODULE_PREFIX}" "${PKGCFG}"
            WORKING_DIRECTORY ${SUBMODULES}
                OUTPUT_FILE ${LOG_DIR}/engine_pkcs11.log)
        find_file(ENGINE_PKCS11 engine_pkcs11.so ${SUBMODULE_PREFIX}/lib/engines /usr/lib/engines)
    endif()
    set (ENV{CFLAGS} ${OLD_CFLAGS})

    if(NOT ENGINE_PKCS11)
        message( FATAL_ERROR "engine_pkcs11 was not found and could not be built. Cannot build tests!" )
    endif()

    # Set the variables to be filled in the header
    set (MODULE_PATH ${LIBSOFTHSM})
    set (ENGINE_PATH ${ENGINE_PKCS11})

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

    # Dirty hack because somehow softhsm does not directly accept our environemt
    # variables, though env reports LD_LIBRARY_PATH correctly... So we write a
    # script, execute that and delete it afterwards.
    file(WRITE
        ${PROJECT_BINARY_DIR}/token_setup.sh
        "export LD_LIBRARY_PATH=$ENV{LD_LIBRARY_PATH} && export SOFTHSM_CONF=softhsm.conf && ${SOFTHSM_BIN} --init-token --slot 0 --label foo --pin 1234 --so-pin 123456 && ${SOFTHSM_BIN} --import ${PROJECT_BINARY_DIR}/tmp/some_key.p8 --slot 0 --pin 1234 --label foo --id 01")
    execute_process(COMMAND sh ${PROJECT_BINARY_DIR}/token_setup.sh
        OUTPUT_QUIET)
    file(REMOVE ${PROJECT_BINARY_DIR}/token_setup.sh)
endif()

# Now we need to put our dynamic settings in the header for tests
configure_file (
    "${CMAKE_CURRENT_SOURCE_DIR}/scep_tests.h.in"
    "${PROJECT_BINARY_DIR}/scep_tests.h"
    )

# Unit tests
foreach (target ${TEST_TARGETS})
    add_executable(test_${target} EXCLUDE_FROM_ALL test_${target}.c)
    add_dependencies(build_test test_${target})
    target_link_libraries(test_${target} ${CHECK_LIBRARIES})
endforeach (target)
add_executable(test_message EXCLUDE_FROM_ALL test_message.c test_message_pkcsreq.c test_message_get_cert_initial.c test_message_get_cert.c test_message_get_crl.c test_message_certrep.c test_message_helper.c)
add_dependencies(build_test test_message)
target_link_libraries(test_message ${CHECK_LIBRARIES})