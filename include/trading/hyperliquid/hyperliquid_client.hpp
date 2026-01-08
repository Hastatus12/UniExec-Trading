#pragma once
#include <memory>
#include <string>

#include "trading/hyperliquid/hyperliquid_types.hpp"

namespace trading::hyperliquid {

class HyperliquidClient final {
public:
    struct Config {
        // optional hook
        // std::function<void(std::string_view)> log;
    };

    explicit HyperliquidClient(std::string private_key, Config cfg = {});
    ~HyperliquidClient();

    HyperliquidClient(const HyperliquidClient&) = delete;
    HyperliquidClient& operator=(const HyperliquidClient&) = delete;
    HyperliquidClient(HyperliquidClient&&) noexcept;
    HyperliquidClient& operator=(HyperliquidClient&&) noexcept;

    ChaseOrderResult chase_order(ChaseOrderRequest& req,
                                 const ChaseOrderOptions& opt = {});
    

    LimitOrderResult limit_order_post(const LimitOrderRequest& req);
    MarketOrderResult market_order_post(const MarketOrderRequest& req);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace trading::hyperliquid
