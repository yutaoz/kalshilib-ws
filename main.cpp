#include <string>
#include <iostream>
#include <chrono>
#include "kalshilib_ws.hpp"

int main() {
  WsEndpoint cfg("api.elections.kalshi.com", "443", "/trade-api/ws/v2");
  KalshiPolicy kp("api id", "path to secret key");

  auto sink = [](WsMessage&& msg) {
    std::cout << "got message: " << msg.payload << "\n";
  };

  WsClient<decltype(sink), KalshiPolicy> client(cfg, kp, sink);
  client.start();

  std::this_thread::sleep_for(std::chrono::seconds(30));

  client.stop();

}
