cmake_minimum_required(VERSION 3.0)
project(bug-debug)

include_directories(libelfin include)
add_executable(debugger debugger.cpp linenoise.c)

add_executable(test test.cpp)
set_target_properties(test PROPERTIES COMPILE_FLAGS "-g -O0")

target_link_libraries(debugger 
                      ${PROJECT_SOURCE_DIR}/libelfin/dwarf/libdwarf++.so
                      ${PROJECT_SOURCE_DIR}/libelfin/elf/libelf++.so)
                      

