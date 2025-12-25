# kalshilib-ws
Header-only c++ websocket client for the kalshi api

## Dependencies
Requires beast and openssl

## Usage
The WsClient needs to take a custom policy for the websocket api such as Kalshi, but one has been provided. You also need an api key from Kalshi for auth.

Messages are consumed by the application, not processed by the header file. This means you need to implement your own sink to handle processes. A very minimal example is in main.cpp.
