#pragma once
#include <string>
#include <chrono>
#include "trading/common/types.hpp"

namespace trading::hyperliquid {

struct ChaseOrderRequest {
    std::string coin;          // es: "BTC"
    double size = 0.0;         // es: 0.00015
    std::string side = "Buy";  // "Buy" o "Sell"

    int asset = 0;             
};

struct ChaseOrderOptions {
    std::chrono::milliseconds timeout{12 * 60 * 60 * 1000};  // 12 ore di default
    int decimal_precision = 12;
};

struct ChaseOrderResult {
    bool success = true;
    std::string error_message;

    std::string order_id;
    double order_price = 0.0;
    double filled_amount = 0.0;

    bool ok() const { return success; }
};

struct LimitOrderRequest {
    std::string coin;
    double size = 0.0;
    std::string side = "Buy";  // "Buy" o "Sell"
    double limit_price = 0.0;  // Prezzo limite
    std::string tif = "Gtc";   // Time In Force: "Alo", "Gtc", "Ioc", "Fok"
    int asset = 0;
};

struct LimitOrderResult {
    bool success = true;
    std::string error_message;
    std::string order_id;
    bool ok() const { return success; }
};

struct MarketOrderRequest {
    std::string coin;
    double size = 0.0;
    std::string side = "Buy";  // "Buy" o "Sell"
    std::string trigger_px = "0";  // Prezzo trigger (0 per market immediato)
    std::string tpsl = "";          // Opzionale: "tp" per take profit, "sl" per stop loss
    int asset = -1;  // -1 per auto-detect, 0+ per asset ID specifico
};

struct MarketOrderResult {
    bool success = true;
    std::string error_message;
    std::string order_id;
    double filled_amount = 0.0;
    double avg_price = 0.0;
    bool ok() const { return success; }
};

} // namespace trading::hyperliquid
