# Installation Guide for JX2 Payment System

## Quick Start - GLIBC Compatibility Issues

**If you're getting GLIBC version errors, see [COMPATIBILITY.md](COMPATIBILITY.md) for detailed solutions.**

### Recommended Solution for Compatibility Issues

Use the no-database version that has minimal dependencies:

```bash
# Build the compatible version
make nodb

# Run the server (only requires basic system libraries)
./bin/paysys
```

This version:
- Runs without MySQL dependencies
- Works with older GLIBC versions
- Includes test accounts (test/test, bishop/1234)
- Fully compatible with Bishop client

## Binary Installation

### Option 1: Use the Pre-compiled Static Binary (Recommended)

The repository includes a fully statically-linked binary with all dependencies embedded:

```bash
# Run the payment system server
./bin/paysys
```

This binary only requires these basic system libraries that are available on all Linux distributions:
- `libc.so.6` (standard C library)
- `/lib64/ld-linux-x86-64.so.2` (dynamic linker)

All other dependencies (MySQL client, OpenSSL, zlib, zstd) are statically linked and embedded in the binary.

### Option 2: Install MySQL Client Library

If you prefer to use the dynamic version or the static version doesn't work, install the MySQL client library:

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install libmysqlclient21
```

**CentOS/RHEL/Fedora:**
```bash
# For RHEL/CentOS 8+
sudo dnf install mysql-libs

# For older versions
sudo yum install mysql-libs
```

**Arch Linux:**
```bash
sudo pacman -S mysql
```

## Building from Source

### Prerequisites

Install development dependencies:

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install build-essential libmysqlclient-dev cmake pkg-config
```

**CentOS/RHEL/Fedora:**
```bash
sudo dnf install gcc-c++ mysql-devel cmake pkgconfig
```

### Build Options

**Standard build (dynamic linking):**
```bash
make all
```

**Static build (embedded MySQL library):**
```bash
make static
```

**Clean build directory:**
```bash
make clean
```

**Build with debug symbols:**
```bash
make debug
```

**No-database version (maximum compatibility):**
```bash
make nodb
```

**Portable binary helper script:**
```bash
./build_portable.sh
```

## Configuration

1. Copy and edit the configuration file:
```bash
cp paysys.ini paysys.ini.local
# Edit paysys.ini.local with your database settings
```

2. Configure your MySQL database:
```sql
CREATE DATABASE jx2_paysys;
CREATE USER 'paysys'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON jx2_paysys.* TO 'paysys'@'localhost';
```

## Running the Server

```bash
# Start the server
./bin/paysys

# Or run in background
nohup ./bin/paysys &
```

The server will:
- Listen on port 8000 by default (configurable in paysys.ini)
- Connect to MySQL if available, otherwise run in test mode
- Log all connections and protocol messages

## Testing

Test the server connection:
```bash
# Basic connection test
nc -z localhost 8000 && echo "Server is running"

# Run the Python test client
python3 test_client.py

# Test with original Bishop client
cd bishop && ./KG_BishopD
```

## Troubleshooting

**Common Issues:**

1. **Binary execution issues**
   - Make executable: `chmod +x bin/paysys`
   - The static binary should work on most Linux distributions without additional dependencies

2. **"Can't connect to MySQL server"**
   - Server will run in test mode without database
   - Check MySQL is running: `sudo systemctl status mysql`
   - Verify connection settings in paysys.ini

3. **Port 8000 already in use**
   - Change port in paysys.ini: `port = 8001`
   - Or kill existing process: `sudo lsof -ti:8000 | xargs kill`