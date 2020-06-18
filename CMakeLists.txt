cmake_minimum_required(VERSION 3.16)
project(capture C)

set(CMAKE_C_STANDARD 99)

add_executable(capture main.c process_packet.c)

target_link_libraries(capture ${CMAKE_SOURCE_DIR}/lib/libpcap.a)
