#include <iostream>

#include <drogon/drogon.h>

#include "config/AppConfig.h"

int main()
{
    const int port = webhawk::config::AppConfig::port();

    std::cout << "Starting WebHawk Lite C++ on port " << port << std::endl;

    drogon::app()
        .addListener("0.0.0.0", port)
        .setLogPath("./logs")
        .setLogLevel(trantor::Logger::kInfo)
        .run();

    return 0;
}