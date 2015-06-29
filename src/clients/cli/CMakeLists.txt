add_executable (scep-client scep-client.c scep-client-util.c scep-client.h configuration.c configuration.h)
target_link_libraries (scep-client scep curl uriparser)