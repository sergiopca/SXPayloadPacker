cmake_minimum_required(VERSION 3.5)

IF (NOT WIN32)
    message(FATAL_ERROR "This program is only for windows")
ENDIF ()

project(SXPayloadPacker)
SET(CMAKE_CXX_FLAGS "-municode -static-libstdc++ -static -lstdc++ -O2")
add_executable(SXPayloadPacker WIN32 main.cpp)
