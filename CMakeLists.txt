cmake_minimum_required(VERSION 3.5)

project(SXPayloadPacker)

SET(CMAKE_CXX_FLAGS "-municode -static-libstdc++ -static -lstdc++ -O2")

add_executable(SXPayloadPacker main.cpp)
