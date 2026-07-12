cmake_minimum_required(VERSION 3.20)

project(webhawk_lite_cpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Drogon CONFIG REQUIRED)

add_executable(webhawk_lite
    src/main.cpp
    src/controllers/HealthController.cpp
)

target_include_directories(webhawk_lite
    PRIVATE
        include
)

target_link_libraries(webhawk_lite
    PRIVATE
        Drogon::Drogon
)