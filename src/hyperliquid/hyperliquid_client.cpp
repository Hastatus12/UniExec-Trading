#include "trading/hyperliquid/hyperliquid_client.hpp"

#include <hyperliquid/exchange.hpp>
#include <hyperliquid/utils/signing.hpp>
#include <hyperliquid/types.hpp>

#include "trading/common/http.hpp"

#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXWebSocket.h>

#include <nlohmann/json.hpp>

#include <curl/curl.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cctype>
#include <iomanip>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

#include <iostream>

using json = nlohmann::json;

namespace trading::hyperliquid {

static bool is_hex_char(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static std::string lower(std::string s) {
    for (char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t totalBytes = size * nmemb;
    auto* response = static_cast<std::string*>(userp);
    response->append(static_cast<char*>(contents), totalBytes);
    return totalBytes;
}

static std::string normalize_privkey(std::string k) {
    // trim
    k.erase(0, k.find_first_not_of(" \t\r\n"));
    if (!k.empty()) k.erase(k.find_last_not_of(" \t\r\n") + 1);

    // strip 0x
    if (k.size() >= 2 && k[0] == '0' && (k[1] == 'x' || k[1] == 'X')) {
        k = k.substr(2);
    }
    return k;
}

static void validate_privkey_or_throw(const std::string& k) {
    if (k.empty()) throw std::runtime_error("Empty private key");
    if (k.size() != 64) throw std::runtime_error("Private key must be 64 hex characters (32 bytes)");
    for (char c : k) {
        if (!is_hex_char(c)) throw std::runtime_error("Private key contains non-hex characters");
    }
}

static std::string to_hl_decimal(double x, int precision = 12) {
    std::ostringstream oss;
    oss.setf(std::ios::fixed);
    oss << std::setprecision(precision) << x;
    std::string s = oss.str();

    if (s.find('.') != std::string::npos) {
        while (!s.empty() && s.back() == '0') s.pop_back();
        if (!s.empty() && s.back() == '.') s.pop_back();
    }
    if (s.empty()) s = "0";
    return s;
}

static bool is_hex_str(const std::string& s) {
    for (char c : s) if (!is_hex_char(c)) return false;
    return true;
}

static std::string normalize_sig_32b_hex(std::string h) {
    h.erase(0, h.find_first_not_of(" \t\r\n"));
    if (!h.empty()) h.erase(h.find_last_not_of(" \t\r\n") + 1);

    if (h.size() >= 2 && h[0] == '0' && (h[1] == 'x' || h[1] == 'X')) {
        h = h.substr(2);
    }
    h = lower(h);

    if (!is_hex_str(h)) throw std::runtime_error("Signature component not hex");
    if (h.size() > 64) throw std::runtime_error("Signature component too long");
    if (h.size() < 64) h = std::string(64 - h.size(), '0') + h;

    return "0x" + h;
}

static std::string side_to_hl(const std::string& s) {
    if (s == "Buy" || s == "buy") return "buy";
    return "sell";
}

struct HyperliquidClient::Impl {
    std::string private_key_norm;   // 64 hex, no 0x
    Config cfg;

    // runtime
    std::mutex mtx;
    std::condition_variable cv;
    std::atomic<bool> stop{false};

    bool has_error = false;
    std::string error_message;

    // order state
    int order_number = 0;
    std::string order_id;
    double order_price = 0.0;
    double filled_amount = 0.0;
    bool awaiting_order = false;

    std::shared_ptr<::hyperliquid::Wallet> wallet;
    std::string address;

    // ws + thread
    ix::WebSocket ws;
    std::thread th_ws;

    static uint64_t now_ms_u64() {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()
        );
    }

    void set_error(std::string msg) {
        {
            std::lock_guard<std::mutex> lk(mtx);
            has_error = true;
            error_message = std::move(msg);
        }
        stop = true;
        cv.notify_all();
        ws.close();
    }

    void reset_state() {
        std::lock_guard<std::mutex> lk(mtx);
        has_error = false;
        error_message.clear();

        order_number = 0;
        order_id.clear();
        order_price = 0.0;
        filled_amount = 0.0;
        awaiting_order = false;
    }

    LimitOrderResult limit_order_post(const LimitOrderRequest& req) {
        LimitOrderResult result;
        
        if (!wallet) {
            std::string pk = normalize_privkey(private_key_norm);
            validate_privkey_or_throw(pk);
            wallet = ::hyperliquid::Wallet::fromPrivateKey(pk);
            if (!wallet) {
                result.success = false;
                result.error_message = "Failed to create wallet";
                return result;
            }
        }
        
        int asset_id = req.asset;
        if (asset_id == 0) {
            asset_id = get_asset_id(req.coin);
        }
        
        const bool is_buy = (req.side == "Buy" || req.side == "buy");
        const uint64_t nonce = now_ms_u64();
        const std::string p_str = to_hl_decimal(req.limit_price, 12);
        const std::string s_str = to_hl_decimal(req.size, 12);
        
        nlohmann::ordered_json action = {
            {"type", "order"},
            {"orders", nlohmann::ordered_json::array({
                nlohmann::ordered_json({
                    {"a", asset_id},
                    {"b", is_buy},
                    {"p", p_str},
                    {"s", s_str},
                    {"r", false},
                    {"t", nlohmann::ordered_json({
                        {"limit", nlohmann::ordered_json({{"tif", req.tif}})}
                    })}
                })
            })},
            {"grouping", "na"}
        };
        
        ::hyperliquid::Signature sig = ::hyperliquid::signL1Action(
            *wallet, action, std::nullopt, nonce, std::nullopt, true
        );
        
        int v_norm = sig.v;
        if (v_norm == 0 || v_norm == 1) v_norm += 27;
        
        const std::string r_hex = normalize_sig_32b_hex(sig.r);
        const std::string s_hex = normalize_sig_32b_hex(sig.s);
        
        nlohmann::ordered_json payload = {
            {"action", action},
            {"nonce", nonce},
            {"signature", {{"r", r_hex}, {"s", s_hex}, {"v", v_norm}}}
        };
        
        std::string payload_str = payload.dump();
        std::cout << "payload_str " << payload_str << std::endl;
        
        trading::http::Response response = trading::http::post_json("https://api.hyperliquid.xyz/exchange", payload_str);
        
        if (response.status != 200) {
            result.success = false;
            result.error_message = "HTTP error: " + std::to_string(response.status) + " - " + response.body;
            return result;
        }
        
        try {
            json response_json = json::parse(response.body);
            if (response_json.contains("status") && response_json["status"] == "ok") {
                if (response_json.contains("response") && 
                    response_json["response"].contains("data") &&
                    response_json["response"]["data"].contains("statuses") &&
                    !response_json["response"]["data"]["statuses"].empty()) {
                    
                    auto st = response_json["response"]["data"]["statuses"][0];
                    if (st.contains("resting")) {
                        result.order_id = std::to_string(st["resting"]["oid"].get<uint64_t>());
                        result.success = true;
                    } else if (st.contains("filled")) {
                        result.order_id = std::to_string(st["filled"]["oid"].get<uint64_t>());
                        result.success = true;
                    } else if (st.contains("error")) {
                        result.success = false;
                        result.error_message = st["error"].get<std::string>();
                    }
                }
            } else {
                result.success = false;
                result.error_message = response.body;
            }
        } catch (const std::exception& e) {
            result.success = false;
            result.error_message = "Failed to parse response: " + std::string(e.what());
        }
        
        return result;
    }

    double get_market_price(const std::string& coin, bool is_buy) {
        std::string url = "https://api.hyperliquid.xyz/info";
        std::string body = "{\"type\":\"l2Book\",\"coin\":\"" + coin + "\"}";
        trading::http::Response resp = trading::http::post_json(url, body);
        
        if (resp.status == 200) {
            try {
                json j = json::parse(resp.body);
                if (j.contains("levels") && j["levels"].is_array() && j["levels"].size() >= 2) {
                    auto levels = j["levels"];
                    if (levels[0].is_array() && !levels[0].empty() && 
                        levels[1].is_array() && !levels[1].empty()) {
                        auto bids = levels[0];
                        auto asks = levels[1];
                        if (bids[0].contains("px") && asks[0].contains("px")) {
                            double bid = std::stod(bids[0]["px"].get<std::string>());
                            double ask = std::stod(asks[0]["px"].get<std::string>());
                            if (is_buy) {
                                return ask;
                            } else {
                                return bid;
                            }
                        }
                    }
                }
            } catch (...) {
            }
        }
        
        std::string body2 = "{\"type\":\"allMids\"}";
        trading::http::Response resp2 = trading::http::post_json(url, body2);
        if (resp2.status == 200) {
            try {
                json j = json::parse(resp2.body);
                if (j.contains(coin) && j[coin].is_string()) {
                    double mid = std::stod(j[coin].get<std::string>());
                    return mid;
                }
            } catch (...) {
            }
        }
        return 0.0;
    }
    
    int get_sz_decimals(int asset_id) {
        std::string url = "https://api.hyperliquid.xyz/info";
        std::string body = "{\"type\":\"meta\"}";
        trading::http::Response resp = trading::http::post_json(url, body);
        
        if (resp.status == 200) {
            try {
                json j = json::parse(resp.body);
                if (j.contains("universe") && j["universe"].is_array()) {
                    if (asset_id < 10000 && asset_id < (int)j["universe"].size()) {
                        if (j["universe"][asset_id].contains("szDecimals")) {
                            return j["universe"][asset_id]["szDecimals"].get<int>();
                        }
                    }
                }
            } catch (...) {
            }
        }
        return 0;
    }
    
    double calculate_slippage_price(const std::string& coin, int asset_id, bool is_buy, double slippage = 0.001, double px = 0.0) {
        if (px == 0.0) {
            px = get_market_price(coin, is_buy);
            if (px == 0.0) return 0.0;
        }
        
        if (slippage > 0.0) {
            px *= (is_buy ? (1.0 + slippage) : (1.0 - slippage));
        }
        
        char buf[64];
        snprintf(buf, sizeof(buf), "%.5g", px);
        double rounded_5sig = std::stod(buf);
        
        int base_decimals = (asset_id >= 10000) ? 8 : 6;
        int sz_decimals = get_sz_decimals(asset_id);
        int final_decimals = base_decimals - sz_decimals;
        if (final_decimals < 0) final_decimals = 0;
        if (final_decimals > 8) final_decimals = 8;
        
        std::ostringstream oss2;
        oss2 << std::fixed << std::setprecision(final_decimals) << rounded_5sig;
        std::string price_str = oss2.str();
        double final_price = std::stod(price_str);
    
        return final_price;
    }

    MarketOrderResult market_order_post(const MarketOrderRequest& req) {
        MarketOrderResult result;
    
        try {
            if (!wallet) {
                std::string pk = normalize_privkey(private_key_norm);
                validate_privkey_or_throw(pk);
    
                wallet = ::hyperliquid::Wallet::fromPrivateKey(pk);
                if (!wallet) {
                    result.success = false;
                    result.error_message = "Failed to create wallet (Wallet::fromPrivateKey returned null)";
                    return result;
                }
            }
    
            // 2) Asset id: 0 è valido. Quindi NON usare 0 come sentinella.
            // Consiglio: usa req.asset = -1 quando non lo sai.
            int asset_id = req.asset;
            if (asset_id < 0) {
                asset_id = get_asset_id(req.coin);
                std::cerr << "DEBUG get_asset_id: coin=" << req.coin << " asset_id=" << asset_id << std::endl;
            }
            if (asset_id < 0) {
                result.success = false;
                result.error_message = "Invalid asset id for coin=" + req.coin;
                return result;
            }
            std::cerr << "DEBUG market_order_post: using asset_id=" << asset_id << " for coin=" << req.coin << std::endl;
    
            const bool is_buy = (req.side == "Buy" || req.side == "buy");
            const uint64_t nonce = now_ms_u64();
            const std::string s_str = to_hl_decimal(req.size, 12);
            
            double limit_px = 0.0;
            if (!req.trigger_px.empty() && req.trigger_px != "0") {
                limit_px = std::stod(req.trigger_px);
            }
            
            limit_px = calculate_slippage_price(req.coin, asset_id, is_buy, 0.001, limit_px);
            if (limit_px == 0.0) {
                result.success = false;
                result.error_message = "Failed to get market price";
                return result;
            }
            
            const std::string p_str = to_hl_decimal(limit_px, 12);
    
            nlohmann::ordered_json order_obj = {
                {"a", asset_id},
                {"b", is_buy},
                {"p", p_str},
                {"s", s_str},
                {"r", false},
                {"t", nlohmann::ordered_json({{"limit", nlohmann::ordered_json({{"tif", "Ioc"}})}})}
            };
    
            nlohmann::ordered_json action = {
                {"type", "order"},
                {"orders", nlohmann::ordered_json::array({order_obj})},
                {"grouping", "na"}
            };
    
            ::hyperliquid::Signature sig = ::hyperliquid::signL1Action(
                *wallet, action, std::nullopt, nonce, std::nullopt, true
            );
    
            int v_norm = sig.v;
            if (v_norm == 0 || v_norm == 1) v_norm += 27;
    
            nlohmann::ordered_json payload = {
                {"action", action},
                {"nonce", nonce},
                {"signature", {
                    {"r", normalize_sig_32b_hex(sig.r)},
                    {"s", normalize_sig_32b_hex(sig.s)},
                    {"v", v_norm}
                }}
            };
    
            auto response = trading::http::post_json(
                "https://api.hyperliquid.xyz/exchange",
                payload.dump(),
                {"Content-Type: application/json"}
            );
    
            if (response.status < 200 || response.status >= 300) {
                result.success = false;
                result.error_message = "HTTP status=" + std::to_string(response.status) + " body=" + response.body;
                return result;
            }
    
            json j = json::parse(response.body);
    
            if (!j.contains("status") || j["status"] != "ok") {
                result.success = false;
                result.error_message = "Exchange returned non-ok: " + response.body;
                return result;
            }
    
            if (!j.contains("response") ||
                !j["response"].contains("data") ||
                !j["response"]["data"].contains("statuses") ||
                !j["response"]["data"]["statuses"].is_array() ||
                j["response"]["data"]["statuses"].empty()) {
                result.success = false;
                result.error_message = "Unexpected response shape: " + response.body;
                return result;
            }
    
            auto st = j["response"]["data"]["statuses"][0];
    
            if (st.contains("resting")) {
                result.order_id = std::to_string(st["resting"]["oid"].get<uint64_t>());
                result.success = true;
                return result;
            }
    
            if (st.contains("filled")) {
                result.order_id = std::to_string(st["filled"]["oid"].get<uint64_t>());
                if (st["filled"].contains("totalSz")) {
                    result.filled_amount = std::stod(st["filled"]["totalSz"].get<std::string>());
                }
                if (st["filled"].contains("avgPx")) {
                    result.avg_price = std::stod(st["filled"]["avgPx"].get<std::string>());
                }
                result.success = true;
                return result;
            }
    
            if (st.contains("error")) {
                result.success = false;
                result.error_message = st["error"].get<std::string>();
                return result;
            }
    
            result.success = false;
            result.error_message = "Unknown status object: " + st.dump();
    
        } catch (const std::exception& e) {
            result.success = false;
            result.error_message = std::string("Exception: ") + e.what();
        }
    
        return result;
    }
    

    std::string format_order_ws(int asset, const std::string& side, double price, double size, int precision) {
        const bool is_buy = (side == "buy");
        const uint64_t nonce = now_ms_u64();

        const std::string p_str = to_hl_decimal(price, precision);
        const std::string s_str = to_hl_decimal(size, precision);

        nlohmann::ordered_json action = {
            {"type", "order"},
            {"orders", nlohmann::ordered_json::array({
                nlohmann::ordered_json({
                    {"a", asset},
                    {"b", is_buy},
                    {"p", p_str},
                    {"s", s_str},
                    {"r", false},
                    {"t", nlohmann::ordered_json({
                        {"limit", nlohmann::ordered_json({{}})}
                    })}
                })
            })},
            {"grouping", "na"}
        };

        ::hyperliquid::Signature sig = ::hyperliquid::signL1Action(
            *wallet, action, std::nullopt, nonce, std::nullopt, true
        );

        int v_norm = sig.v;
        if (v_norm == 0 || v_norm == 1) v_norm += 27;

        const std::string r_hex = normalize_sig_32b_hex(sig.r);
        const std::string s_hex = normalize_sig_32b_hex(sig.s);

        nlohmann::ordered_json payload = {
            {"action", action},
            {"nonce", nonce},
            {"signature", {{"r", r_hex}, {"s", s_hex}, {"v", v_norm}}}
        };

        nlohmann::ordered_json request = {
            {"method", "post"},
            {"id", 256},
            {"request", {{"type", "action"}, {"payload", payload}}}
        };
        return request.dump();
    }

    std::string format_cancel_order_ws(int asset, const std::string& oid) {
        const uint64_t nonce = now_ms_u64();

        nlohmann::ordered_json action = {
            {"type", "cancel"},
            {"cancels", nlohmann::ordered_json::array({
                nlohmann::ordered_json({{"a", asset}, {"o", std::stoull(oid)}})
            })}
        };

        ::hyperliquid::Signature sig = ::hyperliquid::signL1Action(
            *wallet, action, std::nullopt, nonce, std::nullopt, true
        );

        int v_norm = sig.v;
        if (v_norm == 0 || v_norm == 1) v_norm += 27;

        const std::string r_hex = normalize_sig_32b_hex(sig.r);
        const std::string s_hex = normalize_sig_32b_hex(sig.s);

        nlohmann::ordered_json payload = {
            {"action", action},
            {"nonce", nonce},
            {"signature", {{"r", r_hex}, {"s", s_hex}, {"v", v_norm}}}
        };

        nlohmann::ordered_json request = {
            {"method", "post"},
            {"id", 254},
            {"request", {{"type", "action"}, {"payload", payload}}}
        };
        return request.dump();
    }

    // ----- main WS loop -----
    void run_ws(ChaseOrderRequest req, ChaseOrderOptions opt) {
        try {
            // init net + ws
            ix::initNetSystem();
            ws.setUrl("wss://api.hyperliquid.xyz/ws");

            const std::string side = side_to_hl(req.side);

            json price_sub = {
                {"method", "subscribe"},
                {"subscription", {{"type", "l2Book"}, {"coin", req.coin}}}
            };

            json fills_sub = {
                {"method", "subscribe"},
                {"subscription", {{"type", "userFills"}, {"user", address}}}
            };

            ws.setOnMessageCallback([this, req, opt, side, price_sub, fills_sub](const ix::WebSocketMessagePtr& msg) {
                if (msg->type == ix::WebSocketMessageType::Open) {
                    ws.send(price_sub.dump());
                    ws.send(fills_sub.dump());
                    return;
                }
                if (msg->type == ix::WebSocketMessageType::Error) {
                    set_error(std::string("WS error: ") + msg->errorInfo.reason);
                    return;
                }
                if (msg->type == ix::WebSocketMessageType::Close) {
                    // close può arrivare anche “normale” dopo stop()
                    return;
                }
                if (msg->type != ix::WebSocketMessageType::Message) return;

                try {
                    json update = json::parse(msg->str);

                    if (!update.contains("channel")) {
                        return;
                    }
                    const std::string channel = update["channel"].get<std::string>();

                    // 1) Answer to POST
                    if (channel == "post") {
                        std::cout << "POST RESPONSE " << update.dump() << std::endl;
                        // If it's an order response, try to extract oid / error
                        if (update.contains("data") &&
                            update["data"].contains("response") &&
                            update["data"]["response"].contains("payload") &&
                            update["data"]["response"]["payload"].contains("response") &&
                            update["data"]["response"]["payload"]["response"].contains("type") &&
                            update["data"]["response"]["payload"]["response"]["type"] == "order")
                        {
                            auto& resp = update["data"]["response"]["payload"]["response"];
                            if (resp.contains("data") && resp["data"].contains("statuses") &&
                                resp["data"]["statuses"].is_array() && !resp["data"]["statuses"].empty())
                            {
                                auto st = resp["data"]["statuses"][0];

                                std::lock_guard<std::mutex> lk(mtx);

                                if (st.contains("resting")) {
                                    order_number += 1;
                                    order_id = std::to_string(st["resting"]["oid"].get<uint64_t>());
                                    awaiting_order = false;
                                } else if (st.contains("filled")) {
                                    order_number = 1;
                                    order_id = std::to_string(st["filled"]["oid"].get<uint64_t>());
                                    awaiting_order = false;
                                } else if (st.contains("error")) {
                                    std::string error_msg = st["error"].get<std::string>();

                                    bool post_only_error = false;
                                    
                                    if (error_msg.find("Post only order would have immediately matched") != std::string::npos) {
                                        std::cout << "Post only would have immediately matched error" << std::endl;
                                        post_only_error = true;
                                        awaiting_order = false;
                                    }
                                    
                                    if (!post_only_error) {
                                        awaiting_order = false;
                                        lk.~lock_guard();
                                        set_error(std::string("Order error: ") + error_msg);
                                        return;
                                    }
                                } else {
                                    awaiting_order = false;
                                }
                            }
                        }
                        return;
                    }

                    // 2) User fills
                    if (channel == "userFills") {
                        if (update.contains("data") && update["data"].contains("fills")) {
                            bool completed = false;
                            double filled_now = 0.0;

                            {
                                std::lock_guard<std::mutex> lk(mtx);
                                if (order_number >= 1) {
                                    for (int i = 0; i < (int)update["data"]["fills"].size(); i++) {
                                        filled_amount += std::stod(update["data"]["fills"][i]["sz"].get<std::string>());
                                    }
                                    filled_now = filled_amount;
                                    if (filled_amount >= req.size) {
                                        completed = true;
                                    }
                                }
                            }

                            if (completed) {
                                stop = true;
                                cv.notify_all();
                                ws.close();
                            }
                        }
                        return;
                    }

                    // 3) L2Book
                    if (channel == "l2Book") {
                        if (!update.contains("data")) return;
                        auto& d = update["data"];

                        if (!d.contains("levels") || !d["levels"].is_array() || d["levels"].size() < 2) return;
                        if (!d["levels"][0].is_array() || d["levels"][0].empty()) return;
                        if (!d["levels"][1].is_array() || d["levels"][1].empty()) return;

                        if (!d["levels"][0][0].contains("px") || !d["levels"][1][0].contains("px")) return;

                        const double bid = std::stod(d["levels"][0][0]["px"].get<std::string>());
                        const double ask = std::stod(d["levels"][1][0]["px"].get<std::string>());
                        const double px = (side == "buy") ? bid : ask;

                        // state snapshot
                        int ord_num;
                        bool awaiting;
                        double ord_price;
                        std::string oid;

                        {
                            std::lock_guard<std::mutex> lk(mtx);
                            ord_num = order_number;
                            awaiting = awaiting_order;
                            ord_price = order_price;
                            oid = order_id;
                        }

                        // Place initial
                        if (ord_num == 0 && !awaiting) {
                            {
                                std::lock_guard<std::mutex> lk(mtx);
                                awaiting_order = true;
                                order_price = px;
                            }
                            ws.send(format_order_ws(req.asset, side, px, req.size, opt.decimal_precision));
                            return;
                        }

                        // Chase logic: cancel + replace se distanza oltre soglia
                        if (ord_num > 0 && ord_price > 0.0 && !awaiting) {
                            double distance_percent = 0.0;
                            if (side == "buy") {
                                distance_percent = ((bid - ord_price) / ord_price) * 100.0;
                            } else {
                                distance_percent = ((ord_price - ask) / ask) * 100.0;
                            }

                            // Riprezzare se la distanza è > 0.1% (valore hardcoded)
                            const double REPRICE_THRESHOLD_PCT = 0.01;
                            if (distance_percent > REPRICE_THRESHOLD_PCT ||
                                distance_percent < -REPRICE_THRESHOLD_PCT)
                            {
                                // blocca per evitare doppio send
                                {
                                    std::lock_guard<std::mutex> lk(mtx);
                                    if (awaiting_order) return;
                                    awaiting_order = true;
                                }

                                // cancel
                                ws.send(format_cancel_order_ws(req.asset, oid));

                                // new order
                                const double new_px = (side == "buy") ? bid : ask;
                                {
                                    std::lock_guard<std::mutex> lk(mtx);
                                    order_price = new_px;
                                }
                                ws.send(format_order_ws(req.asset, side, new_px, req.size, opt.decimal_precision));
                            }
                        }
                        return;
                    }

                } catch (const std::exception& e) {
                    set_error(std::string("Error processing msg: ") + e.what());
                }
            });

            ws.start();

            // loop “keepalive”
            while (!stop.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }

            ws.close();
        } catch (const std::exception& e) {
            set_error(std::string("Fatal run_ws: ") + e.what());
        }
    }

    int get_asset_id(const std::string& symbol){
        CURL *curl = curl_easy_init();
        std::string responseBody;

        if (curl) {
            struct curl_slist *headers = NULL;
            headers = curl_slist_append(headers, "Content-Type: application/json");
    
            curl_easy_setopt(curl, CURLOPT_URL, "https://api.hyperliquid.xyz/info");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS,
                "{\"type\":\"meta\"}");

            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);

            CURLcode res = curl_easy_perform(curl);

            if (res != CURLE_OK) {
                std::cerr << "curl error: " << curl_easy_strerror(res) << "\n";
                curl_easy_cleanup(curl);
                return -1;
            }

            long statusCode = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &statusCode);
            curl_easy_cleanup(curl);
            curl_slist_free_all(headers);
            
            if (statusCode != 200) {
                std::cerr << "HTTP error: " << statusCode << std::endl;
                return -1;
            }
            
            json responseJson = json::parse(responseBody);
            if (!responseJson.contains("universe") || !responseJson["universe"].is_array()) {
                std::cerr << "Error processing request" << std::endl;
                return -1;
            }
            
            for (int i = 0; i < (int)responseJson["universe"].size(); i++) {
                if (!responseJson["universe"][i].contains("name")) continue;
                
                std::string name = responseJson["universe"][i]["name"].get<std::string>();
                
                if (responseJson["universe"][i].contains("isDelisted") && 
                    responseJson["universe"][i]["isDelisted"].get<bool>()) {
                    continue;
                }
                
                if (name == symbol) {
                    std::cerr << "DEBUG get_asset_id: found " << symbol << " at index " << i << std::endl;
                    return i;
                }
            }
            std::cerr << "DEBUG get_asset_id: symbol " << symbol << " not found in universe" << std::endl;
        }
        return -1;
    }

    void start(ChaseOrderRequest& req, const ChaseOrderOptions& opt) {
        stop = false;
        reset_state();
        
        std::string pk = normalize_privkey(private_key_norm);
        req.asset = get_asset_id(req.coin);
        validate_privkey_or_throw(pk);
        wallet = ::hyperliquid::Wallet::fromPrivateKey(pk);
        if (!wallet) throw std::runtime_error("Wallet::fromPrivateKey returned null");
        address = wallet->address();

        th_ws = std::thread([this, req, opt] { run_ws(req, opt); });
    }

    void stop_and_join() {
        stop = true;
        cv.notify_all();
        ws.close();
        if (th_ws.joinable()) th_ws.join();
    }
};

// -------------------------
// facade
// -------------------------
HyperliquidClient::HyperliquidClient(std::string private_key, Config cfg)
    : impl_(std::make_unique<Impl>()) {
    impl_->private_key_norm = normalize_privkey(std::move(private_key));
    impl_->cfg = cfg;
}

HyperliquidClient::~HyperliquidClient() {
    if (impl_) impl_->stop_and_join();
}

HyperliquidClient::HyperliquidClient(HyperliquidClient&&) noexcept = default;
HyperliquidClient& HyperliquidClient::operator=(HyperliquidClient&&) noexcept = default;

ChaseOrderResult HyperliquidClient::chase_order(ChaseOrderRequest& req,
                                                const ChaseOrderOptions& opt) {
    impl_->start(req, opt);

    // aspetta stop o timeout
    const auto t0 = std::chrono::steady_clock::now();
    while (!impl_->stop.load()) {
        if (std::chrono::steady_clock::now() - t0 > opt.timeout) {
            impl_->set_error("Timeout: order not completed within time limit");
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    ChaseOrderResult out;
    {
        std::lock_guard<std::mutex> lk(impl_->mtx);
        if (impl_->has_error) {
            out.success = false;
            out.error_message = impl_->error_message;
        } else {
            out.success = true;
            out.order_id = impl_->order_id;
            out.order_price = impl_->order_price;
            out.filled_amount = impl_->filled_amount;
        }
    }

    impl_->stop_and_join();
    return out;
}

LimitOrderResult HyperliquidClient::limit_order_post(const LimitOrderRequest& req) {
    return impl_->limit_order_post(req);
}

MarketOrderResult HyperliquidClient::market_order_post(const MarketOrderRequest& req) {
    return impl_->market_order_post(req);
}

} // namespace trading::hyperliquid
