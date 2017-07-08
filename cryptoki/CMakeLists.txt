cmake_minimum_required(VERSION 2.6)
project(pkcs)

add_executable(pkcs main.cpp)

target_link_libraries(pkcs /usr/lib/ClassicClient/libgclib.so)

install(TARGETS pkcs RUNTIME DESTINATION bin)

set(CMAKE_BUILD_TYPE Debug)

