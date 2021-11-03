cmake_minimum_required(VERSION 3.13)

# set source and include directories
file (GLOB SHELL_SRC "src/*.c")

add_executable(rshell ${SHELL_SRC})

# Set compile options
if(${CMAKE_BUILD_TYPE} EQUAL "Debug")
    target_compile_options(rshell PRIVATE "-g3 -lefence")
endif()

# link against libsodium
target_link_libraries(rshell
    PRIVATE
    ${SODIUM_LIB}
    ${PTHREAD_LIB}
    cryptwrapper
)
