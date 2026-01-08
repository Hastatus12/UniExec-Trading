# Build Guide for UniExec‑Trading

This repository provides a C++ library for executing cryptocurrency orders across multiple exchanges, with initial support for Hyperliquid and Bybit. The library is intended to be integrated into automated trading projects and comes with examples that demonstrate how to submit limit, market and chase orders.

## Dependencies

To build the library and the examples you need the following components:

- **C++ compiler** with C++17 support (for example g++ or clang++).
- **libcurl** – used to perform HTTP requests.
- **IXWebSocket** – provides WebSocket client functionality for communicating with Hyperliquid.
- **nlohmann/json** – a header‑only library for JSON serialization and parsing.
- **Hyperliquid C++ SDK** – https://github.com/charlitocrc/hyperliquid-cpp

### Quick installation on Debian/Ubuntu

```bash
sudo apt update
sudo apt install build-essential libcurl4-openssl-dev

# install ixwebsocket and nlohmann/json via vcpkg
git clone https://github.com/microsoft/vcpkg.git
./vcpkg/bootstrap-vcpkg.sh
./vcpkg/vcpkg install ixwebsocket nlohmann-json
```

## Project structure

The project is organized as follows:

- `include/trading/hyperliquid` – public headers such as `hyperliquid_client.hpp`, which defines the `HyperliquidClient` class and request/response structures.
- `src/hyperliquid` – implementation file (`hyperliquid_client.cpp`) that interfaces with the Hyperliquid SDK, normalizes your private key and signs transactions.
- `examples` – sample programs demonstrating basic usage. For instance, `hyperliquid_chase.cpp` shows how to send a chase order.

## Building the library

The repository does not include a ready‑made build system. You can compile the source directly using g++. The following commands create an object file and a static library:

```bash
mkdir -p build

# Compile the library implementation
g++ -std=c++17 -Iinclude \
    -I/path/to/hyperliquid-sdk/include \
    -I/path/to/ixwebsocket/include \
    -I/path/to/nlohmann-json/include \
    -c src/hyperliquid/hyperliquid_client.cpp -o build/hyperliquid_client.o

# Create a static library
ar rcs build/libuniexec_hyperliquid.a build/hyperliquid_client.o
```

Replace `path/to/...` with the actual directories where your dependencies are installed. The resulting `libuniexec_hyperliquid.a` can then be linked into your projects or the provided examples.

## Building the chase order example

The example `hyperliquid_chase.cpp` constructs a `HyperliquidClient`, populates a `ChaseOrderRequest` and submits a chase order. To compile this example, run:

```bash
g++ -std=c++17 -Iinclude \
    -I/path/to/hyperliquid-sdk/include \
    -I/path/to/ixwebsocket/include \
    -I/path/to/nlohmann-json/include \
    examples/hyperliquid_chase.cpp build/hyperliquid_client.o \
    -o build/hyperliquid_chase \
    -L/path/to/ixwebsocket/lib -lixwebsocket \
    -lcurl -pthread
```

Ensure that `libixwebsocket.a` (or the shared library) and `libcurl` are in your library search paths (`/usr/lib`, `/usr/local/lib` or the directory specified with `-L`).

## Private key configuration

The library does not embed any secret keys; you must supply your own Hyperliquid account private key. In the examples the `private_key` variable is initialized to an empty string; you need to replace it with your 64‑character hexadecimal private key. The client implementation checks that the key is not empty and exactly 64 characters long. If the key is missing or malformed, an exception is thrown. For better security, read your key from an environment variable or a protected file instead of hard‑coding it, and assign it to `private_key` before creating the `HyperliquidClient`.

## Running the example

After compiling the executable and assigning your private key, run:

```bash
cd build
./hyperliquid_chase
```

The program will instantiate a client, create a chase order (in the example `coin = "TRX"`, `size = 80`, `side = "Buy"`) and wait for completion. On success it prints the order ID, execution price and filled amount; otherwise it prints an error message. You can adjust the order parameters by editing the variables in the example source.

## Tips and notes

- **Using vcpkg**: If you use [vcpkg](https://github.com/microsoft/vcpkg) to manage dependencies, install `ixwebsocket` and `nlohmann-json` with `vcpkg install ixwebsocket nlohmann-json` and configure CMake with `-DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake`.

- **Hyperliquid SDK**: You can get it here: https://github.com/charlitocrc/hyperliquid-cpp

- **Security**: Your private key grants the ability to sign orders on your account. Do not share it publicly or commit it to a repository. The library normalizes and validates the key but does not expose it.

## Contributing

Contributions are welcome. Please open pull requests with bug fixes or new features, or create issues if you encounter problems. Feel free to use the existing examples as a starting point for your own integrations.

