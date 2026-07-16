#include "config/AppConfig.h"

#include <cstdlib>
#include <string>

using namespace webhawk::config;

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

    return std::string(value);
}

int AppConfig::getEnvInt(
    const std::string& key,
    int defaultValue
)
{
    const char* value = std::getenv(key.c_str());

    if (value == nullptr)
    {
        return defaultValue;
    }

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
    return getEnvInt("PORT", 8080);
}

std::string AppConfig::databaseHost()
{
    return getEnv("DATABASE_HOST", "localhost");
}

int AppConfig::databasePort()
{
    return getEnvInt("DATABASE_PORT", 5435);
}

std::string AppConfig::databaseName()
{
    return getEnv("DATABASE_NAME", "webhawk_cpp");
}

std::string AppConfig::databaseUser()
{
    return getEnv("DATABASE_USER", "webhawk");
}

std::string AppConfig::databasePassword()
{
    return getEnv("DATABASE_PASSWORD", "webhawk_password");
}

std::string AppConfig::databaseConnectionString()
{
    return "host=" + databaseHost()
        + " port=" + std::to_string(databasePort())
        + " dbname=" + databaseName()
        + " user=" + databaseUser()
        + " password=" + databasePassword();
}