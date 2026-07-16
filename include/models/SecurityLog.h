
#pragma once

#include <string>

namespace webhawk::models
{
struct SecurityLog
{
    int id{};
    int backendId{};
    std::string ipAddress;
    std::string method;
    std::string endpoint;
    std::string attackType;
    bool isBlocked{};
    std::string requestData;
    std::string createdAt;
};
}