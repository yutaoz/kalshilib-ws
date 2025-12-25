#ifndef WS_CLIENT_H
#define WS_CLIENT_H

#include <string>
#include <vector>
#include <thread>
#include <fstream>
#include <sstream>
#include <chrono>
#include <deque>
#include <mutex>
#include <condition_variable>

#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <openssl/pem.h>
#include <openssl/evp.h>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

// struct for websocket messages to pass to our sink
struct WsMessage {
  std::string payload;
  bool is_text;
  std::chrono::steady_clock::time_point recv_ts;
};

struct WsEndpoint {
  std::string host;
  std::string port;
  std::string path;

  WsEndpoint(std::string ws_host, std::string ws_port, std::string ws_path) :
    host(ws_host), port(ws_port), path(ws_path) {}

};

// a ws policy for kalshi, currently on_message is unused and on_open
// is a default example subscription message - should be adapted
struct KalshiPolicy {

  std::string access_key;
  std::string private_key_path;

  KalshiPolicy(std::string key_id, std::string path) :
    access_key(key_id),
    private_key_path(path)
  {}

  EVP_PKEY* load_private_key(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
      throw std::runtime_error("Cannot open " + filepath);
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string pem_data = buffer.str();

    BIO* bio = BIO_new_mem_buf(pem_data.data(), pem_data.size());

    if (!bio) {
      throw std::runtime_error("Failed to create bio");
    }

    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!key) {
      throw std::runtime_error("Failed to parse private key");
    }

    return key;
  }

  std::string sign_pss_text(EVP_PKEY* private_key, const std::string& text) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
      throw std::runtime_error("Failed to create context");
    }

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, private_key) <= 0) {
      EVP_MD_CTX_free(ctx);
      throw std::runtime_error("Failed to initialize signing");
    }

    EVP_PKEY_CTX* pkey_ctx = EVP_MD_CTX_pkey_ctx(ctx);
    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST);
    EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256());

    size_t sig_len = 0;
    if (EVP_DigestSign(ctx, nullptr, &sig_len, 
                      reinterpret_cast<const unsigned char*>(text.data()), 
                      text.size()) <= 0) {
      EVP_MD_CTX_free(ctx);
      throw std::runtime_error("Failed to get signature length");
    }
    
    std::vector<unsigned char> signature(sig_len);
    if (EVP_DigestSign(ctx, signature.data(), &sig_len,
                      reinterpret_cast<const unsigned char*>(text.data()),
                      text.size()) <= 0) {
      EVP_MD_CTX_free(ctx);
      throw std::runtime_error("RSA sign PSS failed");
    }
    
    EVP_MD_CTX_free(ctx);
    
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new(BIO_s_mem());
    BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    
    BIO_write(b64, signature.data(), sig_len);
    BIO_flush(b64);
    
    BUF_MEM* buffer;
    BIO_get_mem_ptr(b64, &buffer);
    
    std::string result(buffer->data, buffer->length);
    
    BIO_free_all(b64);
    EVP_PKEY_free(private_key);
    return result;
  }

  long long get_timestamp_ms() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()
    );
    return ms.count();
  }

  // headers for ws handhsake
  std::vector<std::pair<std::string, std::string>> headers() {
    EVP_PKEY* private_key = load_private_key(private_key_path);

    long long timestamp = get_timestamp_ms();
    std::string timestamp_string = std::to_string(timestamp);
    std::string path = "/trade-api/ws/v2";
    
    std::string msg = timestamp_string + "GET" + path;

    std::string signature = sign_pss_text(private_key, msg);

    return {
      {"User-Agent", "KalshBook/1.0"},
      {"KALSHI-ACCESS-KEY", access_key},
      {"KALSHI-ACCESS-SIGNATURE", signature},
      {"KALSHI-ACCESS-TIMESTAMP", timestamp_string},
    };
  }

  // after websocket handshake
  void on_open(auto&& send_text) {
    std::string subscription_message = R"({
      "id": 1,
      "cmd":"subscribe",
      "params": {
        "channels": ["ticker"]
      }
    })";

    send_text(subscription_message);
    std::cout << "Sent subscription message" << std::endl;
  }

  // each received msg
  void on_message(std::string_view msg) {
      std::cout << "Received: " << msg << "\n";
  }

  // on error/close
  void on_error(std::string_view what) {
    std::cerr << "Error: " << what << "\n";
  }
};

// websocket client
template <class Sink, class Policy>
class WsClient {
    std::jthread worker;

    Policy policy;
    Sink sink;
    WsEndpoint cfg;

    ssl::context ssl_ctx;
    net::io_context ioc;
    using ws_stream = websocket::stream<beast::ssl_stream<tcp::socket>>;
    std::optional<ws_stream> ws;

    beast::flat_buffer read_buffer_;

  public:

    explicit WsClient(WsEndpoint ws_cfg, Policy ws_policy, Sink ws_sink) :
      cfg(std::move(ws_cfg)), 
      policy(std::move(ws_policy)),
      sink(std::move(ws_sink)),
      ssl_ctx(ssl::context::tlsv12_client)
      {
        ssl_ctx.set_default_verify_paths();
        ssl_ctx.set_verify_mode(ssl::verify_peer);
      }

    void start() {
      worker = std::jthread([this](std::stop_token st){
        std::cout << "Worker thread spawned: " << cfg.host << std::endl;
        connect_and_handshake();

        policy.on_open([this](const std::string& msg){
          this->send_text(std::move(msg));
        });

        async_read();
        async_write();

        ioc.run();

      });
    }

    void stop() {
      worker.request_stop();
        std::cout << "thread killed" << std::endl;
    }

    void send_text(std::string msg) {
      bool should_trigger = false;
      {
        std::lock_guard lk(out_mtx_);
        out_q_.push_back(std::move(msg));
        should_trigger = !write_in_flight_;
      }

      if (should_trigger) {
        net::post(ioc, [this]{async_write(); });
      }
    }

    void flush_writes() {
      std::deque<std::string> local;
      {
        std::lock_guard lk(out_mtx_);
        local.swap(out_q_);
      }

      for (auto& s : local) {
        if (!ws || !ws->is_open()) return;
        ws->text(true);
        ws->write(net::buffer(s));
      }
    }

  private:
    std::mutex out_mtx_;
    std::deque<std::string> out_q_;
    std::condition_variable_any out_cv_;
    bool write_in_flight_ = false;

    void connect_and_handshake() {
      tcp::resolver resolver(ioc);
      auto results = resolver.resolve(cfg.host, cfg.port);

      ws.emplace(ioc, ssl_ctx);

      net::connect(get_lowest_layer(*ws), results);

      if (!SSL_set_tlsext_host_name(ws->next_layer().native_handle(),
                                    cfg.host.c_str())) {
        throw beast::system_error{
          static_cast<int>(::ERR_get_error()),
          net::error::get_ssl_category()
        };
      }

      ws->next_layer().handshake(ssl::stream_base::client);

      ws->set_option(websocket::stream_base::decorator(
        [this](websocket::request_type& req) {
          for (auto& [key, value] : policy.headers()) {
            req.set(key, value);
          }
        }
      ));

      ws->handshake(cfg.host, cfg.path);
      
      std::cout << "connected and handshake complete!" << std::endl;
    }

    void do_subscribe();

    void async_read() {
      ws->async_read(read_buffer_, [this](beast::error_code ec, std::size_t) {
        if (ec) return;
        
        WsMessage msg {
          .payload = beast::buffers_to_string(read_buffer_.data()),
          .is_text = ws->got_text(),
          .recv_ts = std::chrono::steady_clock::now()
        };
        
        sink(std::move(msg));
        read_buffer_.consume(read_buffer_.size());
        
        async_read(); 
      });
    }

    void async_write() {
      std::lock_guard lk(out_mtx_);
      
      if (out_q_.empty() || write_in_flight_) {
        return;
      }
      
      write_in_flight_ = true;
      
      ws->async_write(
        net::buffer(out_q_.front()), 
        [this](beast::error_code ec, std::size_t) {
          std::lock_guard lk(out_mtx_);
          
          out_q_.pop_front();
          write_in_flight_ = false;
          
          if (!ec && !out_q_.empty()) {
            net::post(ioc, [this]{ async_write(); });
          }
        }
      );
    }

    void read_loop(std::stop_token st) {
      beast::flat_buffer buffer;

      try {
        while(!st.stop_requested() && ws && ws->is_open()) {
          flush_writes();
          {
            std::unique_lock lk(out_mtx_);
            if (out_q_.empty()) {
              out_cv_.wait_for(lk, std::chrono::milliseconds(50));
            }
          }

          ws->read(buffer);
          WsMessage msg {
            .payload = beast::buffers_to_string(buffer.data()),
            .is_text = ws->got_text(),
            .recv_ts = std::chrono::steady_clock::now()
          };

          sink(std::move(msg));
          //policy.on_message(message);
          buffer.consume(buffer.size());
        }
      } catch (const std::exception& e) {
          std::cerr << "Read loop error: " << e.what() << "\n";
          policy.on_error(e.what());
      }
    }
};

#endif
