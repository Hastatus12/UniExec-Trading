#pragma once
#include <string>
#include <chrono>

namespace trading {

enum class Side { Buy, Sell };

inline std::string to_bybit_side(Side s) {
    return (s == Side::Buy) ? "Buy" : "Sell";
}

struct Credentials {
    std::string api_key;
    std::string api_secret;
};

using Symbol = std::string;

} // namespace trading