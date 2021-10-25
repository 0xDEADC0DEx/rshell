cmake_minimum_required(VERSION 3.19)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(rshell LANGUAGES C)


# Set build type
if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	message(STATUS "Setting build type to 'Release' as none was specified.")
	set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)

	# Set the possible values of build type for cmake-gui
	set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif ()

find_library(SODIUM_LIB sodium)
find_library(PTHREAD_LIB pthread)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

include_directories (${CMAKE_SOURCE_DIR}/cryptwrapper/include)
include_directories (${CMAKE_SOURCE_DIR}/rshell/include)
include_directories (${CMAKE_SOURCE_DIR}/rshellserver/include)

add_subdirectory(cryptwrapper)
add_subdirectory(rshell)
add_subdirectory(rshellserver)
