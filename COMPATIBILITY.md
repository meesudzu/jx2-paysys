# GLIBC Compatibility Issue and Solutions

## Problem
The compiled binary requires newer GLIBC versions (2.25-2.38) that may not be available on older Linux systems.

## Solutions

### Solution 1: Use the No-Database Binary (Recommended)
We've provided a special build that doesn't require MySQL libraries and has minimal dependencies:

```bash
# This binary only requires basic system libraries (libc.so.6)
./bin/paysys
```

**Features of no-database version:**
- Runs in test mode without requiring MySQL installation
- Much smaller binary size (1.5MB vs 8.6MB)
- Only depends on basic system libraries
- Includes test accounts: `test/test` and `bishop/1234`
- Full protocol compatibility with Bishop client

### Solution 2: Compile on Your System
For the best compatibility, compile the server on your target system:

#### Prerequisites
```bash
# CentOS/RHEL/Rocky Linux
sudo yum install gcc-c++ make mysql-devel

# Ubuntu/Debian  
sudo apt-get install g++ make libmysqlclient-dev

# SUSE/OpenSUSE
sudo zypper install gcc-c++ make libmysqlclient-devel
```

#### Compilation Commands
```bash
# Clone the repository
git clone https://github.com/meesudzu/jx2-paysys.git
cd jx2-paysys

# Build options:
make nodb      # No-database version (recommended for testing)
make all       # Full version with MySQL support
make static    # Statically linked version
```

### Solution 3: Using Docker (Alternative)
If compilation is not possible, you can run the server in a container:

```bash
# Create a simple Dockerfile
echo 'FROM ubuntu:20.04
RUN apt-get update && apt-get install -y libmysqlclient21
COPY bin/paysys /usr/local/bin/
COPY paysys.ini /etc/
EXPOSE 8000
CMD ["/usr/local/bin/paysys"]' > Dockerfile

# Build and run
docker build -t jx2-paysys .
docker run -p 8000:8000 jx2-paysys
```

### Solution 4: System-Specific Instructions

#### For CentOS 7/RHEL 7 (GLIBC 2.17)
```bash
# Use the no-database version
./bin/paysys  # Should work with minimal dependencies
```

#### For Ubuntu 16.04/18.04 (GLIBC 2.23-2.27)
```bash
# May need to compile locally
sudo apt-get install g++ make
make nodb
```

## Testing the Server

Once running, test with the Bishop client:
```bash
cd bishop
./KG_BishopD
```

Or use the Python test client:
```bash
python3 test_client.py
```

## Troubleshooting

### If you still get GLIBC errors:
1. Check your system's GLIBC version: `ldd --version`
2. Use the no-database version: `make nodb`
3. Compile on your target system for best compatibility
4. Consider using a container solution

### If the server won't start:
1. Check port 8000 is available: `netstat -an | grep 8000`
2. Verify config file exists: `ls -la paysys.ini`
3. Run with verbose output for debugging

## Contact
If you continue to have compatibility issues, please provide:
- Your Linux distribution and version
- Output of `ldd --version`
- Any error messages when running the server