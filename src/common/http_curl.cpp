#include <curl/curl.h>
#include <string>
#include <vector>
#include <iostream>
#include <nlohmann/json.hpp>
#include "trading/common/http.hpp"

using json = nlohmann::json;

namespace trading::http {

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    size_t total_size = size * nmemb;
    userp->append((char*)contents, total_size);
    return total_size;
}

Response post_json(std::string url, std::string body, std::vector<std::string> headers, long timeout_ms) {
    Response result;
    CURL* curl = curl_easy_init();
    
    if (!curl) {
        result.error = "Failed to initialize CURL";
        result.status = 0;
        return result;
    }
    
    struct curl_slist* header_list = nullptr;
    header_list = curl_slist_append(header_list, "Content-Type: application/json");
    
    for (const auto& h : headers) {
        header_list = curl_slist_append(header_list, h.c_str());
    }
    
    std::string response_body;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        result.error = curl_easy_strerror(res);
        result.status = 0;
    } else {
        long status_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
        result.status = status_code;
        result.body = response_body;
        std::cout << "response_body " << response_body << std::endl;
    }
    
    curl_slist_free_all(header_list);
    curl_easy_cleanup(curl);
    
    return result;
}

} // namespace trading::http
