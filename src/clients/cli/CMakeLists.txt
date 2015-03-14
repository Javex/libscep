add_executable (scep-client scep-client.c scep-client-util.c scep-client.h)
target_link_libraries (scep-client scep curl uriparser)