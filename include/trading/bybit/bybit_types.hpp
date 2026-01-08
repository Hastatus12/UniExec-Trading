#pragma once
#include <string>
#include <chrono>
#include <optional>
#include "trading/common/types.hpp"

namespace trading::bybit {

struct ChaseOrderRequest {
    trading::Symbol symbol;
    double qty = 0.0;
    trading::Side side = trading::Side::Buy;
};

struct ChaseOrderOptions {
    std::chrono::milliseconds timeout{60'000};
};

struct ChaseOrderResult {
    std::string order_id;
    double last_price = 0.0;

    bool success = true;             // se false -> c'è stato errore
    std::string error_message = "";  // testo errore

    bool ok() const { return success; }
};

} // namespace trading::bybit