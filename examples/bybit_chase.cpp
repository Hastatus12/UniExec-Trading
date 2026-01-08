#include <iostream>
#include "trading/bybit/bybit_client.hpp"

int main() {
    trading::Credentials creds{
        "", //API KEY
        "" //API SECRET
    };

    trading::bybit::BybitClient client(creds);

    trading::bybit::ChaseOrderRequest req{
        "BTCUSDT",
        0.001,
        trading::Side::Buy
    };

    trading::bybit::ChaseOrderOptions opt;
    // opt.timeout = std::chrono::seconds(60);

    auto res = client.chase_order(req, opt);

    if (!res.ok()) {
        std::cout << "ERROR: " << res.error_message << "\n";
        return 1;
    }

    std::cout << "OK: order_id=" << res.order_id << "\n";
    return 0;
}
