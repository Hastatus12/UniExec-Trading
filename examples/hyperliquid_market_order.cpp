#include <iostream>
#include "trading/hyperliquid/hyperliquid_client.hpp"

int main() {
    try {
        std::string private_key = "";
        trading::hyperliquid::HyperliquidClient hl(private_key);
        
        trading::hyperliquid::MarketOrderRequest req;
        req.coin = "TRX";
        req.size = 80;
        req.side = "Buy";
        req.trigger_px = "0";  // 0 per market order immediato
        // req.tpsl = "";      // Opzionale: "tp" per take profit, "sl" per stop loss
        
        auto res = hl.market_order_post(req);
        
        if (!res.ok()) {
            std::cerr << "HYPERLIQUID ERROR: " << res.error_message << "\n";
            return 1;
        }
        
        std::cout << "HL OK. order_id=" << res.order_id;
        if (res.filled_amount > 0) {
            std::cout << " filled=" << res.filled_amount 
                      << " avg_price=" << res.avg_price;
        }
        std::cout << "\n";
        
    } catch (const std::exception& e) {
        std::cerr << "FATAL ERROR: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

