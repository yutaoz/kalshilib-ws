/opt/homebrew/opt/llvm/bin/clang++ -std=c++23 \
  -I/opt/homebrew/include \
  -L/opt/homebrew/lib \
  -lssl -lcrypto \
  main.cpp -o kalshbook
