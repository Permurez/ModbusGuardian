cmake_minimum_required(VERSION 3.10)
project(ModbusGuardian)

set(CMAKE_CXX_STANDARD 17)

set(NPCAP_SDK "C:/npcap-sdk") 

include_directories(${NPCAP_SDK}/Include)

link_directories(${NPCAP_SDK}/Lib/x64) 

add_executable(ModbusGuardian src/main.cpp)

target_link_libraries(ModbusGuardian wpcap Packet)