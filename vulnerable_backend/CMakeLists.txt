cmake_minimum_required(VERSION 3.20)

project(
    webhawk_vulnerable_backend
    VERSION 1.0.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Drogon CONFIG REQUIRED)

add_executable(
    vulnerable_backend
    main.cpp
)

target_link_libraries(
    vulnerable_backend
    PRIVATE
        Drogon::Drogon
)