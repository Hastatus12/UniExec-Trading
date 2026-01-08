#pragma once
#include <memory>
#include "trading/common/types.hpp"
#include "trading/bybit/bybit_types.hpp"

namespace trading::bybit {

class BybitClient final {
public:
    struct Config {
        // puoi aggiungere log callback, recv_window, ping, ecc.
        int recv_window_ms = 8000;
    };

    BybitClient(trading::Credentials creds, Config cfg = {});
    ~BybitClient();

    BybitClient(const BybitClient&) = delete;
    BybitClient& operator=(const BybitClient&) = delete;
    BybitClient(BybitClient&&) noexcept;
    BybitClient& operator=(BybitClient&&) noexcept;

    ChaseOrderResult chase_order(const ChaseOrderRequest& req,
                                 const ChaseOrderOptions& opt = {});

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace trading::bybit
