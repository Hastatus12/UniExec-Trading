#include <iostream>
#include "trading/hyperliquid/hyperliquid_client.hpp"

int main() {
    try {
        std::string private_key = "";
        trading::hyperliquid::HyperliquidClient hl(private_key);
        
        trading::hyperliquid::LimitOrderRequest req;
        req.coin = "TRX";
        req.size = 80;
        req.side = "Sell";
        req.limit_price = 0.324180;
        req.tif = "Gtc";  // Time In Force: "Alo", "Gtc", "Ioc"
        
        auto res = hl.limit_order_post(req);
        
        if (!res.ok()) {
            std::cerr << "HL ERROR: " << res.error_message << "\n";
            return 1;
        }
        
        std::cout << "HL OK. order_id=" << res.order_id << "\n";
        
    } catch (const std::exception& e) {
        std::cerr << "FATAL ERROR: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

