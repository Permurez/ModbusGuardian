cmake_minimum_required(VERSION 3.20)
project(modbus_guardian C CXX)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Shared frame codec: pure C, no I/O
add_library(mbframe STATIC src/mbframe.c)
target_include_directories(mbframe PUBLIC include) 
target_compile_options(mbframe PRIVATE -Wall -Wextra -Wpedantic -g)

# Traffic generator / Modbus TCP client
add_executable(mbgen src/mbgen.c)
target_link_libraries(mbgen PRIVATE mbframe)
target_compile_options(mbgen PRIVATE -Wall -Wextra -Wpedantic -g)

# Passive sniffer / IDS
add_executable(modbus-guardian src/main.cpp)
target_link_libraries(modbus-guardian PRIVATE mbframe pcap)
target_compile_options(modbus-guardian PRIVATE -Wall -Wextra -Wpedantic -g)