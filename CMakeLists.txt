cmake_minimum_required(VERSION 3.10)
project(ToyDBG)

add_compile_options(-std=c++11)

include_directories(lib/libelfin lib/linenoise include)

file(GLOB SOURCES "src/*.cpp")

add_executable(ToyDBG ${SOURCES} lib/linenoise/linenoise.c)

add_executable(HelloWorld examples/helloworld.cpp)