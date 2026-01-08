#include <iostream>
#include "trading/hyperliquid/hyperliquid_client.hpp"

int main() {
    try {
        std::string private_key = "";
        trading::hyperliquid::HyperliquidClient hl(private_key);
        
        trading::hyperliquid::ChaseOrderRequest req;
        req.coin = "BTC";
        req.size = 0.00015;
        req.side = "Buy";
        
        trading::hyperliquid::ChaseOrderOptions opt;
        
        auto res = hl.chase_order(req, opt);
        
        if (!res.ok()) {
            std::cerr << "HL ERROR: " << res.error_message << "\n";
            return 1;
        }
        
        std::cout << "HL OK. order_id=" << res.order_id
                  << " order_price=" << res.order_price
                  << " filled=" << res.filled_amount << "\n";
        
    } catch (const std::exception& e) {
        std::cerr << "FATAL ERROR: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
