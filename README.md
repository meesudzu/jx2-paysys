# JX2 Payment System Server

A C++ implementation of the JX2 payment system server, reverse engineered from the original binaries.

## Overview

This project implements a new payment system server for JX2 (Jx2) game servers, compatible with the original Bishop client and protocol. The implementation is based on reverse engineering of the original payment system binaries:

- **Priority Logic Sources:**
  1. `KG_SimulatePaysys_FS.exe` (highest priority)
  2. `vzopaysys.exe` (medium priority)
  3. `paysys` (Linux binary, lowest priority)

## Features

- TCP server listening on configurable port (default: 8000)
- MySQL database integration for account management
- Protocol handling for Bishop client connections
- Support for user authentication, login/logout operations
- Configurable return codes for different operations
- Multi-threaded client handling

## Building

### Requirements

- C++11 compatible compiler
- MySQL development libraries
- pthreads support

### Using Make

```bash
make all
```

### Using CMake

```bash
mkdir build
cd build
cmake ..
make
```

## Configuration

Edit `paysys.ini` to configure the server:

```ini
[Paysys]
szPaysysIPAddress=127.0.0.1
nPaysysPort=8000
nMaxAcceptEachWait=512
nMaxRecvBufSizePerSocket=2048
nMaxSendBufSizePerSocket=2048
nMaxEventCount=512

[Mysql]
Host=127.0.0.1
Username=root
Password=1234
DBName=jx2_paysys
```

## Database Setup

1. Create MySQL database:
```sql
CREATE DATABASE jx2_paysys;
```

2. Import the provided schema:
```bash
mysql -u root -p jx2_paysys < paysys-win/paysys.sql
```

## Running

```bash
./bin/paysys
```

The server will start and listen on the configured port for Bishop client connections.

## Protocol Analysis

The implementation is based on analysis of:
- Network packet captures (`player-login.pcap`, `bishop-connect-capture.pcap`)
- Original binary reverse engineering
- Configuration files from original system

## Testing

Use the provided Bishop client (`bishop/KG_BishopD`) to test connections:

```bash
cd bishop
./KG_BishopD
```

## Project Structure

```
src/
├── main.cpp              # Main application entry point
├── config_manager.h/cpp  # Configuration file handling
├── database_manager.h/cpp # MySQL database operations
├── paysys_server.h/cpp   # TCP server implementation
└── protocol_handler.h/cpp # JX2 protocol message handling
```

## License

This project is for educational and research purposes, based on reverse engineering of existing game server binaries.