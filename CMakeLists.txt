cmake_minimum_required(VERSION 3.10)
project(ToyDBG)

add_compile_options(-std=c++11)
set(CMAKE_BUILD_TYPE Debug)

include_directories(lib/libelfin lib/linenoise include)

file(GLOB SOURCES "src/*.cpp")

add_executable(ToyDBG ${SOURCES} lib/linenoise/linenoise.c)

add_executable(HelloWorld examples/helloworld.cpp)
set_target_properties(HelloWorld PROPERTIES COMPILE_FLAGS "-g -gdwarf-4 -O0")

add_executable(Stack examples/stack_unwinding.cpp)
set_target_properties(Stack PROPERTIES COMPILE_FLAGS "-g -gdwarf-4 -O0")

add_custom_target(
   libelfin
   COMMAND make
   WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/lib/libelfin
)

target_link_libraries(ToyDBG ${PROJECT_SOURCE_DIR}/lib/libelfin/dwarf/libdwarf++.so)
target_link_libraries(ToyDBG ${PROJECT_SOURCE_DIR}/lib/libelfin/elf/libelf++.so)

add_dependencies(ToyDBG libelfin)