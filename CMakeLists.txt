cmake_minimum_required(VERSION 3.20)

project(webhawk_lite_cpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Drogon CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

find_package(libpqxx CONFIG QUIET)

if(libpqxx_FOUND)
    set(PQXX_TARGET libpqxx::pqxx)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PQXX REQUIRED IMPORTED_TARGET libpqxx)
    set(PQXX_TARGET PkgConfig::PQXX)
endif()

add_executable(webhawk_lite
    src/main.cpp

    src/controllers/HealthController.cpp
    src/controllers/DatabaseHealthController.cpp
    src/controllers/AuthController.cpp
    src/controllers/BackendController.cpp
    src/controllers/SecurityController.cpp

    src/config/AppConfig.cpp
    src/database/Database.cpp

    src/repositories/UserRepository.cpp
    src/repositories/SessionRepository.cpp
    src/repositories/BackendRepository.cpp
    src/repositories/SecurityLogRepository.cpp
    src/repositories/RateLimitRepository.cpp

    src/services/AuthService.cpp
    src/services/BackendService.cpp
    src/services/SecurityService.cpp

    src/security/PasswordHasher.cpp
    src/security/JwtService.cpp
    src/security/AuthMiddleware.cpp
    src/security/ApiKeyGenerator.cpp
    src/security/SqlInjectionDetector.cpp
)

target_include_directories(webhawk_lite
    PRIVATE
        include
)

target_link_libraries(webhawk_lite
    PRIVATE
        Drogon::Drogon
        ${PQXX_TARGET}
        OpenSSL::Crypto
)

include(CTest)

if(BUILD_TESTING)
    add_executable(sql_injection_detector_tests
        tests/SqlInjectionDetectorTests.cpp
        src/security/SqlInjectionDetector.cpp
    )

    target_include_directories(
        sql_injection_detector_tests
        PRIVATE
            include
    )

    target_link_libraries(
        sql_injection_detector_tests
        PRIVATE
            Drogon::Drogon
    )

    add_test(
        NAME sql_injection_detector_tests
        COMMAND sql_injection_detector_tests
    )
endif()