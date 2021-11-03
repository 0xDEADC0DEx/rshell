cmake_minimum_required(VERSION 3.13)

# set source and include directories
file (GLOB SERVER_SRC "src/*.c")

add_executable(rshell_listen ${SERVER_SRC})

# Set compile options
if(${CMAKE_BUILD_TYPE} EQUAL "Debug")
    target_compile_options(rshell_listen PRIVATE "-g3 -lefence")
endif()

# link against libsodium
target_link_libraries(rshell_listen
    PRIVATE
    ${SODIUM_LIB}
    ${PTHREAD_LIB}
    cryptwrapper
)
