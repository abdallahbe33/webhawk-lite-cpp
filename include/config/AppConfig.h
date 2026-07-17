#pragma once

#include <string>

namespace webhawk::config
{
class AppConfig
{
public:
    static int port();

    static std::string databaseHost();
    static int databasePort();
    static std::string databaseName();
    static std::string databaseUser();
    static std::string databasePassword();

    static std::string databaseConnectionString();

    static std::string jwtSecretKey();
    static int jwtExpirationSeconds();

private:
    static std::string getEnv(
        const std::string& key,
        const std::string& defaultValue
    );

    static int getEnvInt(
        const std::string& key,
        int defaultValue
    );
};
}
