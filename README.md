# Kerberos Under Partial Compromise (Schnorr Multi-Signatures)

## Overview
This project implements a Kerberos-inspired authentication system in C++17 using independent Schnorr signatures from multiple authorities.

Security goal:
- The system remains secure if at most one authority is compromised.
- A ticket is valid only when at least two different authority signatures verify.

Cryptography used:
- Schnorr signatures (manual implementation)
- SHA-256 (manual implementation)
- AES-256-CBC with manual PKCS#7 padding
- BigInt arithmetic (manual implementation)

No asymmetric crypto library is used.

## Architecture
Processes:
- `AS1`, `AS2`, `AS3` (authentication authorities)
- `TGS1`, `TGS2`, `TGS3` (ticket-granting authorities)
- Service server
- Client

Each authority has its own independent key pair:
- Private key: `x_i in Z_q`
- Public key: `y_i = g^x_i mod p`

Validation rule:
- TGT and service tickets must include signatures from at least two distinct authorities.

## Repository Layout
- `master_keygen.cpp` - generates parameters/keys/config files
- `as_node.cpp` - AS authority node
- `tgs_node.cpp` - TGS authority node
- `service_server.cpp` - service ticket verifier + service endpoint
- `client.cpp` - protocol client
- `attacks.cpp` - mandatory attack simulations
- `src/*.cpp`, `include/*.h` - crypto, ticket, networking core
- `stress.sh` - concurrent stress testing script

## Build
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j4
```

## Run (Default Ports)
1. Generate keys/config:
```bash
./build/master_keygen --regen
```

2. Start AS nodes (3 terminals):
```bash
./build/as_node 1 8001
./build/as_node 2 8002
./build/as_node 3 8003
```

3. Start TGS nodes (3 terminals):
```bash
./build/tgs_node 1 8101
./build/tgs_node 2 8102
./build/tgs_node 3 8103
```

4. Start service server:
```bash
./build/service_server fileserver 9001
```

5. Run client:
```bash
./build/client alice alice123 fileserver
```

Expected result:
- Authentication succeeds
- Ticket validation requires at least two valid authority signatures

## Attack Scenarios
Run:
```bash
./build/attacks
```

Scenarios:
1. Single malicious authority forging ticket
2. Modified ticket payload
3. Replay of old partial signature
4. Leakage of one authority private key
5. Authority offline
6. Ticket with only one valid signature

## Stress Testing
Default stress run:
```bash
./stress.sh
```

Isolated-port stress run (recommended if defaults are already in use):
```bash
AS_PORTS=8201,8202,8203 \
TGS_PORTS=8301,8302,8303 \
SERVICE_PORT=9201 \
CLIENTS=60 PARALLEL=12 \
LOG_DIR=stress_logs_iso \
./stress.sh
```

## Notes
- If old binaries are still running on default ports, restart servers from the latest `build/` output.
- The assignment allows C/C++/Python; this submission is C++.
