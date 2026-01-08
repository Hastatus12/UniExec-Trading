#pragma once
#include <string>
#include <vector>

namespace trading::http {
    struct Response { 
        long status; 
        std::string body; 
        std::string error; 
    };
    Response post_json(std::string url, std::string body, std::vector<std::string> headers = {}, long timeout_ms = 10000);
}


