#include "models/SecurityLog.h"

#include <sstream>

using namespace webhawk::models;

Json::Value SecurityLog::toJson() const
{
    Json::Value body;

    body["id"] = id;
    body["backend_id"] = backendId;
    body["ip_address"] = ipAddress;
    body["method"] = method;
    body["endpoint"] = endpoint;
    body["attack_type"] = attackType;
    body["is_blocked"] = isBlocked;
    body["created_at"] = createdAt;

    Json::Value parsedRequestData;
    Json::CharReaderBuilder builder;
    std::string errors;
    std::istringstream input(requestData);

    if (
        Json::parseFromStream(
            builder,
            input,
            &parsedRequestData,
            &errors
        )
    )
    {
        body["request_data"] =
            parsedRequestData;
    }
    else
    {
        body["request_data"] =
            requestData;
    }

    return body;
}