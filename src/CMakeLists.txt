set (CMAKE_C_FLAGS "-Wall -Werror")

add_library (scep SHARED scep.c operation.c util.c configuration.c message.c)
target_link_libraries (scep uriparser crypto curl m)