cmake_minimum_required(VERSION "3.1")
set (CMAKE_CXX_STANDARD 17) 
project("haze")

add_subdirectory(TinyInst)

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

include_directories(TinyInst)

target_link_libraries(haze tinyinst)

