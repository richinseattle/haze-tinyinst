cmake_minimum_required(VERSION "3.1")
set (CMAKE_CXX_STANDARD 17) 
project("haze")

add_subdirectory(TinyInst)

add_executable(haze
  haze.cpp
 "mutator.cpp" "mutator.h" "util.cpp" "util.h" "fuzzqueue.cpp" "fuzzqueue.h")

include_directories(TinyInst)

target_link_libraries(haze tinyinst)

