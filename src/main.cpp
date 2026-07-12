#include <cstdlib>
#include <iostream>
#include <string>

#include <drogon/drogon.h>

int main()
{
    int port = 8080;

    if (const char* portFromEnv = std::getenv("PORT"))
    {
        port = std::stoi(portFromEnv);
    }

    std::cout << "Starting WebHawk Lite C++ on port " << port << std::endl;

    drogon::app()
        .addListener("0.0.0.0", port)
        .setLogPath("./logs")
        .setLogLevel(trantor::Logger::kInfo)
        .run();

    return 0;
}