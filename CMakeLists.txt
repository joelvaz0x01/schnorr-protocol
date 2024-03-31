cmake_minimum_required(VERSION 3.28.1)
project(schnorr_protocol C)
set(CMAKE_C_STANDARD 23)

if (MSVC)
    set(CMAKE_C_FLAGS "/W4 /WX")
    set(CMAKE_C_FLAGS_RELEASE "/O2")
elseif (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
    set(CMAKE_C_FLAGS "-Wall -Wextra -Werror -Wpedantic")
    set(CMAKE_C_FLAGS_RELEASE "-O3")
endif ()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)
set(SCHNORR_PROTOCOL schnorr_protocol.out)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
link_libraries(${OPENSSL_LIBRARIES})
add_executable(${SCHNORR_PROTOCOL} src/main.c)
