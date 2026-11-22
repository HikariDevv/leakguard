cmake_minimum_required(VERSION 3.16)
project(leakguard VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(leakguard
    src/main.cpp
    src/entropy.cpp
    src/rules.cpp
    src/scanner.cpp
    src/reporter.cpp
)

if(MSVC)
    target_compile_options(leakguard PRIVATE /W4 /O2)
else()
    target_compile_options(leakguard PRIVATE -Wall -Wextra -Wpedantic -O2)
endif()
