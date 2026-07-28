cmake_minimum_required(VERSION 3.20)

project(
    webhawk_lite
    VERSION 0.1.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/Zc:__cplusplus)
endif()

find_package(Drogon CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

include(CTest)

add_executable(
    webhawk_lite

    src/main.cpp

    src/controllers/HealthController.cpp
    src/controllers/DatabaseHealthController.cpp
    src/controllers/AuthController.cpp
    src/controllers/BackendController.cpp
    src/controllers/SecurityController.cpp
    src/controllers/RateLimitController.cpp
    src/controllers/SecurityLogController.cpp
    src/controllers/AnalyticsController.cpp
    src/controllers/ProxyController.cpp

    src/config/AppConfig.cpp
    src/database/Database.cpp

    src/models/SecurityLog.cpp

    src/repositories/UserRepository.cpp
    src/repositories/SessionRepository.cpp
    src/repositories/BackendRepository.cpp
    src/repositories/SecurityLogRepository.cpp
    src/repositories/RateLimitRepository.cpp
    src/repositories/AnalyticsRepository.cpp

    src/services/AuthService.cpp
    src/services/BackendService.cpp
    src/services/SecurityService.cpp
    src/services/SecurityLogService.cpp
    src/services/AnalyticsService.cpp
    src/services/ProxyService.cpp

    src/security/PasswordHasher.cpp
    src/security/JwtService.cpp
    src/security/AuthMiddleware.cpp
    src/security/ApiKeyGenerator.cpp
    src/security/SqlInjectionDetector.cpp
    src/security/XssDetector.cpp
    src/security/RequestScanner.cpp
    src/security/RateLimitPolicy.cpp
    src/security/RateLimiter.cpp

    src/proxy/ProxyUtils.cpp
)

target_include_directories(
    webhawk_lite
    PRIVATE
        include
)

target_link_libraries(
    webhawk_lite
    PRIVATE
        Drogon::Drogon
        OpenSSL::Crypto
)

if(BUILD_TESTING)
    add_executable(
        sql_injection_detector_tests
        tests/SqlInjectionDetectorTests.cpp
        src/security/SqlInjectionDetector.cpp
    )

    target_include_directories(
        sql_injection_detector_tests
        PRIVATE
            include
    )

    add_test(
        NAME sql_injection_detector_tests
        COMMAND sql_injection_detector_tests
    )

    add_executable(
        xss_detector_tests
        tests/XssDetectorTests.cpp
        src/security/XssDetector.cpp
    )

    target_include_directories(
        xss_detector_tests
        PRIVATE
            include
    )

    add_test(
        NAME xss_detector_tests
        COMMAND xss_detector_tests
    )

    add_executable(
        request_scanner_tests
        tests/RequestScannerTests.cpp
        src/security/RequestScanner.cpp
        src/security/SqlInjectionDetector.cpp
        src/security/XssDetector.cpp
    )

    target_include_directories(
        request_scanner_tests
        PRIVATE
            include
    )

    add_test(
        NAME request_scanner_tests
        COMMAND request_scanner_tests
    )

    add_executable(
        rate_limit_policy_tests
        tests/RateLimitPolicyTests.cpp
        src/security/RateLimitPolicy.cpp
    )

    target_include_directories(
        rate_limit_policy_tests
        PRIVATE
            include
    )

    add_test(
        NAME rate_limit_policy_tests
        COMMAND rate_limit_policy_tests
    )

    add_executable(
        security_log_model_tests
        tests/SecurityLogModelTests.cpp
        src/models/SecurityLog.cpp
    )

    target_include_directories(
        security_log_model_tests
        PRIVATE
            include
    )

    target_link_libraries(
        security_log_model_tests
        PRIVATE
            Drogon::Drogon
    )

    add_test(
        NAME security_log_model_tests
        COMMAND security_log_model_tests
    )

    add_executable(
        proxy_utils_tests
        tests/ProxyUtilsTests.cpp
        src/proxy/ProxyUtils.cpp
    )

    target_include_directories(
        proxy_utils_tests
        PRIVATE
            include
    )

    add_test(
        NAME proxy_utils_tests
        COMMAND proxy_utils_tests
    )
    target_link_libraries(
        sql_injection_detector_tests
        PRIVATE
            Drogon::Drogon
    )

    target_link_libraries(
        xss_detector_tests
        PRIVATE
            Drogon::Drogon
    )

    target_link_libraries(
        request_scanner_tests
        PRIVATE
            Drogon::Drogon
    )

    target_link_libraries(
        rate_limit_policy_tests
        PRIVATE
            Drogon::Drogon
    )

    

    target_link_libraries(
        proxy_utils_tests
        PRIVATE
            Drogon::Drogon
    )
endif()