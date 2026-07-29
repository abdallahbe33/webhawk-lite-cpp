#include "config/AppConfig.h"

#include <cstdlib>
#include <string>

namespace webhawk::config
{
std::string AppConfig::getEnv(
    const std::string& key,
    const std::string& defaultValue
)
{
    const char* value = std::getenv(key.c_str());

    if (value == nullptr)
    {
        return defaultValue;
    }

    const std::string result(value);

    if (result.empty())
    {
        return defaultValue;
    }

    return result;
}

int AppConfig::getEnvInt(
    const std::string& key,
    int defaultValue
)
{
    const std::string value =
        getEnv(
            key,
            std::to_string(defaultValue)
        );

    try
    {
        return std::stoi(value);
    }
    catch (...)
    {
        return defaultValue;
    }
}

int AppConfig::port()
{
    const int value =
        getEnvInt(
            "PORT",
            8080
        );

    return value < 1 ? 8080 : value;
}

std::string AppConfig::databaseHost()
{
    return getEnv(
        "DATABASE_HOST",
        "127.0.0.1"
    );
}

int AppConfig::databasePort()
{
    const int value =
        getEnvInt(
            "DATABASE_PORT",
            5435
        );

    return value < 1 ? 5435 : value;
}

std::string AppConfig::databaseName()
{
    return getEnv(
        "DATABASE_NAME",
        "webhawk_cpp"
    );
}

std::string AppConfig::databaseUser()
{
    return getEnv(
        "DATABASE_USER",
        "webhawk"
    );
}

std::string AppConfig::databasePassword()
{
    return getEnv(
        "DATABASE_PASSWORD",
        "webhawk_password"
    );
}

std::string AppConfig::databaseConnectionString()
{
    return
        "host=" + databaseHost() +
        " port=" + std::to_string(databasePort()) +
        " dbname=" + databaseName() +
        " user=" + databaseUser() +
        " password=" + databasePassword();
}

std::string AppConfig::jwtSecretKey()
{
    return getEnv(
        "JWT_SECRET_KEY",
        "development-jwt-secret-change-me"
    );
}

int AppConfig::jwtExpirationSeconds()
{
    const int value =
        getEnvInt(
            "JWT_EXPIRATION_SECONDS",
            86400
        );

    return value < 1 ? 86400 : value;
}

int AppConfig::rateLimitRequests()
{
    const int value =
        getEnvInt(
            "RATE_LIMIT_REQUESTS",
            100
        );

    return value < 1 ? 1 : value;
}

int AppConfig::rateLimitWindowSeconds()
{
    const int value =
        getEnvInt(
            "RATE_LIMIT_WINDOW_SECONDS",
            60
        );

    return value < 1 ? 1 : value;
}

int AppConfig::rateLimitBlockSeconds()
{
    const int value =
        getEnvInt(
            "RATE_LIMIT_BLOCK_SECONDS",
            60
        );

    return value < 1 ? 1 : value;
}

int AppConfig::proxyTimeoutSeconds()
{
    const int value =
        getEnvInt(
            "PROXY_TIMEOUT_SECONDS",
            10
        );

    return value < 1 ? 1 : value;
}

int AppConfig::proxyMaxBodyBytes()
{
    const int value =
        getEnvInt(
            "PROXY_MAX_BODY_BYTES",
            1048576
        );

    return value < 1024 ? 1024 : value;
}
}