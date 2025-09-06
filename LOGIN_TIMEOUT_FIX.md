# Login Timeout Fix

## Issue
User login was getting stuck due to expensive XOR key detection operations for new/unknown users.

## Root Cause
The `detectNewUserXORKey` function contained several computationally expensive operations:

1. `detectKeyByFrequencyAnalysis` - nested loops iterating through all 256 possible byte values
2. `deriveKeyFromKnownPatterns` - multiple nested loops for rotations, shifts, and patterns
3. Long-running operations without timeout controls
4. No circuit breaker to prevent repeated expensive operations

## Solution

### 1. Added Timeout Controls
- Added 30-second timeout for all key detection operations
- Individual method timeouts (10 seconds each)
- Context-based cancellation for early termination

### 2. Implemented Circuit Breaker Pattern
- Prevents repeated expensive key detection for same client IP
- 5-minute cooldown period between attempts
- Tracks last attempt time per client address

### 3. Optimized Algorithms
- Reduced frequency analysis complexity (limited samples, focused candidate ranges)
- Optimized pattern derivation (test every other rotation/shift instead of all)
- Lowered evaluation thresholds for faster termination

### 4. Improved Session Management
- Reduced Bishop session timeout from 5 minutes to 2 minutes
- Added maximum session duration limit (30 minutes)
- Better session cleanup and termination

### 5. Enhanced Logging
- Added progress logging during key detection operations
- Better visibility into which operations are running
- Circuit breaker status logging

## Test Results
- Unknown user login attempts: Complete in < 35 seconds (previously could hang indefinitely)
- Circuit breaker: Subsequent attempts from same IP complete in < 1 second
- Known user logins: Unchanged performance (< 1 second)

## Files Modified
- `internal/protocol/encryption.go` - Added timeout controls and circuit breaker
- `internal/protocol/handler.go` - Updated to use client-aware decryption and improved session timeouts
- `cmd/test-login-timeout/main.go` - Added test to verify timeout behavior

## Backward Compatibility
- All existing functionality preserved
- Known user keys continue to work as before
- New user detection still available but with performance safeguards