# Copyright 2020 Google LLC
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     https://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION "3.1")
set (CMAKE_CXX_STANDARD 17)

add_subdirectory(TinyInst)

project("haze")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/third_party/Mersenne)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/TinyInst)

add_library(fuzzerlib STATIC
  client.cpp
  client.h
  directory.cpp
  directory.h
  fuzzer.cpp
  fuzzer.h
  instrumentation.cpp
  instrumentation.h
  mutator.cpp
  mutator.h
  mutex.cpp
  mutex.h
  prng.cpp
  prng.h
  third_party/Mersenne/mersenne.cpp
  third_party/Mersenne/mersenne.h
  runresult.h
  sample.cpp
  sample.h
  sampledelivery.cpp
  sampledelivery.h
  server.cpp
  server.h
  thread.cpp
  thread.h
  )

add_dependencies(fuzzerlib tinyinst)
target_link_libraries(fuzzerlib tinyinst)

if (WIN32)
  target_link_libraries(fuzzerlib "Ws2_32.lib")
endif()

add_executable(fuzzer
  main.cpp
)

target_link_libraries(fuzzer fuzzerlib)

add_executable(test
  test.cpp
  )

add_executable(haze 
	haze.cpp 
	util.cpp 
	libFuzzer/FuzzerCrossOver.cpp
	libFuzzer/FuzzerDataFlowTrace.cpp
	libFuzzer/FuzzerDriver.cpp
	libFuzzer/FuzzerExtFunctionsDlsym.cpp
	libFuzzer/FuzzerExtFunctionsWeak.cpp
	libFuzzer/FuzzerExtFunctionsWindows.cpp
	libFuzzer/FuzzerExtraCounters.cpp
	libFuzzer/FuzzerFork.cpp
	libFuzzer/FuzzerIO.cpp
	libFuzzer/FuzzerIOPosix.cpp
	libFuzzer/FuzzerIOWindows.cpp
	libFuzzer/FuzzerLoop.cpp
	libFuzzer/FuzzerMerge.cpp
	libFuzzer/FuzzerMutate.cpp
	libFuzzer/FuzzerSHA1.cpp
	libFuzzer/FuzzerTracePC.cpp
	libFuzzer/FuzzerUtil.cpp
	libFuzzer/FuzzerUtilDarwin.cpp
	libFuzzer/FuzzerUtilFuchsia.cpp
	libFuzzer/FuzzerUtilLinux.cpp
	libFuzzer/FuzzerUtilPosix.cpp
	libFuzzer/FuzzerUtilWindows.cpp
)

target_link_libraries(haze fuzzerlib)