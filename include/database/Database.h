#pragma once

#include <string>

namespace webhawk::database
{
class Database
{
public:
    static bool canConnect();

    static int countQuery(
        const std::string& sql
    );
};
}