#include "trading/bybit/bybit_client.hpp"

// private dependencies
#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXWebSocket.h>
#include <mbedtls/md.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>

#include <iostream>

using json = nlohmann::json;

namespace trading::bybit {

struct PriceUpdate { double ask = 0.0; double bid = 0.0; };

struct OrderState {
    int order_number = 0;
    std::string order_id;
    double order_price = 0.0;
    bool awaiting_order = false;
    bool filled = false;
};

static std::string hex_lower(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) oss << std::setw(2) << (int)data[i];
    return oss.str();
}

static std::string hmac_sha256_hex(const std::string& key, const std::string& msg) {
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) throw std::runtime_error("mbedtls_md_info_from_type failed");

    unsigned char out[32];
    int rc = mbedtls_md_hmac(
        info,
        reinterpret_cast<const unsigned char*>(key.data()), key.size(),
        reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
        out
    );
    if (rc != 0) throw std::runtime_error("mbedtls_md_hmac failed");
    return hex_lower(out, sizeof(out));
}

// ============================================================================
//                            IMPLEMENTAZIONE (pImpl)
// ============================================================================
struct BybitClient::Impl {
    trading::Credentials creds;
    Config cfg;

    // costante interna (non modificabile dall'utente)
    static constexpr double AMEND_THRESHOLD_PCT = 0.002;

    // stato + sync (ex-globali)
    std::mutex mtx;
    std::condition_variable cv;
    std::deque<PriceUpdate> price_q;

    std::atomic<bool> stop{false};

    // order state
    OrderState order;

    // websockets 
    ix::WebSocket public_ws;
    ix::WebSocket trade_ws;
    ix::WebSocket private_ws;

    // threads
    std::thread th_public;
    std::thread th_trade;
    std::thread th_private;
    std::thread th_chase;

    bool has_error = false;
    std::string error_message;

    // --- util ---
    static long long now_ms() {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    }

    std::string format_order(const std::string& ticker, double price, double qty, trading::Side side) {
        long long ts = now_ms();
        return json{
            {"reqId", "order-" + std::to_string(ts)},
            {"header", {{"X-BAPI-TIMESTAMP", std::to_string(ts)},
                        {"X-BAPI-RECV-WINDOW", std::to_string(cfg.recv_window_ms)}}},
            {"op", "order.create"},
            {"args", json::array({{
                {"category", "linear"},
                {"orderType", "Limit"},
                {"timeInForce", "PostOnly"},
                {"price", std::to_string(price)},
                {"qty", std::to_string(qty)},
                {"side", trading::to_bybit_side(side)},
                {"symbol", ticker},
                {"reduceOnly", false},
                {"closeOnTrigger", false}
            }})}
        }.dump();
    }

    std::string format_amend(const std::string& order_id, const std::string& ticker,
                             trading::Side side, double price, double qty) {
        long long ts = now_ms();
        return json{
            {"reqId", "amend-" + std::to_string(ts)},
            {"header", {{"X-BAPI-TIMESTAMP", std::to_string(ts)},
                        {"X-BAPI-RECV-WINDOW", std::to_string(cfg.recv_window_ms)}}},
            {"op", "order.amend"},
            {"args", json::array({{
                {"category", "linear"},
                {"symbol", ticker},
                {"timeInForce", "PostOnly"},
                {"orderId", order_id},
                {"price", std::to_string(price)},
                {"qty", std::to_string(qty)},
                {"side", trading::to_bybit_side(side)}
            }})}
        }.dump();
    }

    void set_error(const std::string& msg) {
        {
            std::lock_guard<std::mutex> lk(mtx);
            has_error = true;
            error_message = msg;
        }
        stop = true;
        cv.notify_all();
    
        // chiusure best-effort
        public_ws.close();
        trade_ws.close();
        private_ws.close();
    }

    void run_public_stream(std::string ticker) {
        ix::initNetSystem();
        public_ws.setUrl("wss://stream.bybit.com/v5/public/linear");
        public_ws.setPingInterval(20);

        const std::string subMsg = json{
            {"req_id", "sub"},
            {"op", "subscribe"},
            {"args", {"orderbook.1." + ticker}}
        }.dump();

        public_ws.setOnMessageCallback([this, subMsg, ticker](const ix::WebSocketMessagePtr& msg) {
            if (msg->type == ix::WebSocketMessageType::Open) {
                public_ws.send(subMsg);
                return;
            }
            if (msg->type != ix::WebSocketMessageType::Message) return;

            try {
                json data = json::parse(msg->str);

                // ignora response di subscribe
                if (data.contains("success") || data.contains("ret_msg") || data.contains("retCode")) {
                    // handler not found => stop
                    if (data.contains("ret_msg")) {
                        auto ret = data["ret_msg"].get<std::string>();
                        if (ret.find("handler not found") != std::string::npos) {
                            set_error(data["ret_msg"].get<std::string>());
                            return;
                        }
                    }
                    return;
                }

                if (!data.contains("data") || !data["data"].contains("a") || !data["data"].contains("b")) return;
                if (!data["data"]["a"].is_array() || !data["data"]["b"].is_array()) return;
                if (data["data"]["a"].empty() || data["data"]["b"].empty()) return;

                double ask = std::stod(data["data"]["a"][0][0].get<std::string>());
                double bid = std::stod(data["data"]["b"][0][0].get<std::string>());

                {
                    std::lock_guard<std::mutex> lk(mtx);
                    price_q.push_back({ask, bid});
                }
                cv.notify_one();
            } catch (...) {
                // logging here
            }
        });

        public_ws.start();

        while (!stop.load()) std::this_thread::sleep_for(std::chrono::milliseconds(50));
        public_ws.close();
    }

    void run_trade_stream() {
        ix::initNetSystem();
        trade_ws.setUrl("wss://stream.bybit.com/v5/trade");
        trade_ws.setPingInterval(20);

        long long expires = now_ms() + 10000;
        std::string payload = "GET/realtime" + std::to_string(expires);
        std::string sig = hmac_sha256_hex(creds.api_secret, payload);

        const std::string authMsg = json{
            {"req_id", "auth"},
            {"op", "auth"},
            {"args", {creds.api_key, expires, sig}}
        }.dump();

        trade_ws.setOnMessageCallback([this, authMsg](const ix::WebSocketMessagePtr& msg) {
            if (msg->type == ix::WebSocketMessageType::Open) {
                trade_ws.send(authMsg);
                return;
            }
            if (msg->type != ix::WebSocketMessageType::Message) return;

            try {
                json update = json::parse(msg->str);
                std::cout << "Trade stream update received: " << update.dump() << "\n";

                if (update.contains("retCode") && update["retCode"] == 10001 &&
                    update.contains("retMsg") && update["retMsg"] == "Params Error") {
                    set_error(update["retMsg"].get<std::string>());
                    return;
                }

                if (update.contains("retCode") && update["retCode"] == 110007 &&
                    update.contains("retMsg") && update["retMsg"] == "ab not enough for new order") {
                    set_error(update["retMsg"].get<std::string>());
                    return;
                }

                // esempi come nel tuo codice
                if (update.contains("retCode") && update["retCode"] == 10001 &&
                    update.contains("retMsg") && update["retMsg"] == "order not modified") {
                    std::lock_guard<std::mutex> lk(mtx);
                    order.awaiting_order = false;
                }

                if (update.contains("retCode") && update["retCode"] == 110007 &&
                    update.contains("retMsg") && update["retMsg"] == "ab not enough for new order") {
                    stop = true;
                    cv.notify_all();
                    trade_ws.close();
                }

                if (update.contains("retCode") && update["retCode"] == 10001 &&
                    update.contains("retMsg") && update["retMsg"] == "The number of contracts exceeds minimum limit allowed") {
                    set_error(update["retMsg"].get<std::string>());
                    return;
                }

            } catch (...) {}
        });

        trade_ws.start();

        while (!stop.load()) std::this_thread::sleep_for(std::chrono::milliseconds(50));
        trade_ws.close();
    }

    void run_private_stream() {
        ix::initNetSystem();
        private_ws.setUrl("wss://stream.bybit.com/v5/private");
        private_ws.setPingInterval(20);

        long long expires = now_ms() + 10000;
        std::string payload = "GET/realtime" + std::to_string(expires);
        std::string sig = hmac_sha256_hex(creds.api_secret, payload);

        const std::string authMsg = json{{"req_id","auth"},{"op","auth"},{"args",{creds.api_key,expires,sig}}}.dump();
        const std::string subMsg  = json{{"reqId","sub-order"},{"op","subscribe"},{"args",{"order"}}}.dump();

        private_ws.setOnMessageCallback([this, authMsg, subMsg](const ix::WebSocketMessagePtr& msg) {
            if (msg->type == ix::WebSocketMessageType::Open) {
                private_ws.send(authMsg);
                private_ws.send(subMsg);
                return;
            }
            if (msg->type != ix::WebSocketMessageType::Message) return;

            try {
                json update = json::parse(msg->str);

                // fill completo (leavesQty == 0) => stop
                if (update.contains("topic") && update["topic"] == "order" &&
                    update.contains("data") && update["data"].is_array() && !update["data"].empty()) {

                    std::string leavesQty = update["data"][0].value("leavesQty", "");
                    if (leavesQty == "0") {
                        std::lock_guard<std::mutex> lk(mtx);
                        order.filled = true;
                        stop = true;
                        cv.notify_all();
                        private_ws.close();
                        trade_ws.close();
                        return;
                    }

                    if (update["data"][0].contains("rejectReason") &&
                        update["data"][0]["rejectReason"] == "EC_NoError" &&
                        update["data"][0].contains("orderStatus") &&
                        update["data"][0]["orderStatus"] == "New") {

                        std::lock_guard<std::mutex> lk(mtx);
                        order.order_number += 1;
                        order.order_price = std::stod(update["data"][0]["price"].get<std::string>());
                        order.order_id = update["data"][0]["orderId"].get<std::string>();
                        order.awaiting_order = false;
                    }
                }
            } catch (...) {}
        });

        private_ws.start();
        while (!stop.load()) std::this_thread::sleep_for(std::chrono::milliseconds(50));
        private_ws.close();
    }

    // ------------------------- CHASE LOOP -------------------------
    void run_chase_loop(ChaseOrderRequest req, ChaseOrderOptions opt) {
        while (!stop.load()) {
            PriceUpdate u;
            {
                std::unique_lock<std::mutex> lk(mtx);
                cv.wait(lk, [&] { return stop.load() || !price_q.empty(); });
                if (stop.load()) break;
                u = price_q.front();
                price_q.pop_front();
            }

            const double current_price = (req.side == trading::Side::Buy) ? u.bid : u.ask;

            // state snapshot
            std::string order_id;
            double order_price;
            int order_number;
            bool awaiting;

            {
                std::lock_guard<std::mutex> lk(mtx);
                order_id = order.order_id;
                order_price = order.order_price;
                order_number = order.order_number;
                awaiting = order.awaiting_order;
            }

            // place initial
            if (order_number == 0 && !awaiting) {
                std::cout << "Placing initial order!!!!!!: " << current_price << "\n";
                const std::string msg = format_order(req.symbol, current_price, req.qty, req.side);
                trade_ws.send(msg);
                std::cout << "Sent order message!!!!!!: " << msg << "\n";
                std::lock_guard<std::mutex> lk(mtx);
                order.awaiting_order = true;
                continue;
            }

            // amend
            if (order_number >= 1 && !awaiting) {
                double distance_pct = std::abs(current_price - order_price) / std::abs(current_price) * 100.0;

                bool should_amend = false;
                if (req.side == trading::Side::Buy)
                    should_amend = (distance_pct > AMEND_THRESHOLD_PCT && current_price > order_price);
                else
                    should_amend = (distance_pct > AMEND_THRESHOLD_PCT && current_price < order_price);

                if (should_amend && !order_id.empty()) {
                    const std::string amend = format_amend(order_id, req.symbol, req.side, current_price, req.qty);
                    trade_ws.send(amend);
                    std::lock_guard<std::mutex> lk(mtx);
                    order.awaiting_order = true;
                }
            }
        }
    }

    void start(const ChaseOrderRequest& req, const ChaseOrderOptions& opt) {
        stop = false;
        {
            std::lock_guard<std::mutex> lk(mtx);
            order = OrderState{};
            price_q.clear();
        }

        th_trade   = std::thread([this]{ run_trade_stream(); });
        th_public  = std::thread([this, sym=req.symbol]{ run_public_stream(sym); });
        th_private = std::thread([this]{ run_private_stream(); });
        th_chase   = std::thread([this, req, opt]{ run_chase_loop(req, opt); });
    }

    void stop_and_join() {
        stop = true;
        cv.notify_all();

        // chiudi ws (safe best-effort)
        public_ws.close();
        private_ws.close();
        trade_ws.close();

        auto join_if = [](std::thread& t){ if (t.joinable()) t.join(); };
        join_if(th_chase);
        join_if(th_private);
        join_if(th_public);
        join_if(th_trade);
    }
};

// ============================================================================
//                         BybitClient (facade)
// ============================================================================
BybitClient::BybitClient(trading::Credentials c, Config cfg)
    : impl_(std::make_unique<Impl>()) {
    impl_->creds = std::move(c);
    impl_->cfg = cfg;
}

BybitClient::~BybitClient() {
    if (impl_) impl_->stop_and_join();
}

BybitClient::BybitClient(BybitClient&&) noexcept = default;
BybitClient& BybitClient::operator=(BybitClient&&) noexcept = default;

ChaseOrderResult BybitClient::chase_order(const ChaseOrderRequest& req,
                                         const ChaseOrderOptions& opt) {
    impl_->start(req, opt);

    // attende finché stop o timeout
    const auto start = std::chrono::steady_clock::now();
    while (!impl_->stop.load()) {
        if (std::chrono::steady_clock::now() - start > opt.timeout) {
            impl_->stop = true;
            impl_->cv.notify_all();
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
            out.order_id = impl_->order.order_id;
            out.last_price = impl_->order.order_price;
        }
    }

    impl_->stop_and_join();
    return out;
}

} // namespace trading::bybit
