cmake_minimum_required(VERSION 3.13)

# set source and include directories
file (GLOB CRYPT_SRC "src/*.c")

add_library(cryptwrapper STATIC ${CRYPT_SRC})
