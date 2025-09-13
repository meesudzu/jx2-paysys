package main

import (
	"fmt"
	"time"

	"jx2-paysys/internal/protocol"
)

func main() {
	fmt.Println("Testing login timeout fix...")

	// Test data that would trigger expensive key detection (random data)
	unknownUserData := []byte{
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
		0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
		0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
		0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
		0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
	}

	// Make sure we have enough data
	fullData := make([]byte, 225) // Typical user login packet size
	for i := 0; i < len(fullData); i++ {
		fullData[i] = unknownUserData[i%len(unknownUserData)]
	}

	clientAddr := "127.0.0.1:12345"

	// Test 1: First attempt should try key detection (with timeout)
	fmt.Printf("Test 1: First attempt for unknown user (should timeout quickly)...\n")
	start := time.Now()
	
	// This should trigger key detection but timeout quickly
	result := protocol.DecryptXORWithClientAddr(fullData, clientAddr)
	duration := time.Since(start)
	
	fmt.Printf("First attempt took: %v\n", duration)
	fmt.Printf("Result length: %d bytes\n", len(result))
	
	if duration > 35*time.Second {
		fmt.Printf("❌ FAIL: First attempt took too long (%v), expected < 35s\n", duration)
	} else {
		fmt.Printf("✅ PASS: First attempt completed in reasonable time (%v)\n", duration)
	}

	// Test 2: Second attempt should be blocked by circuit breaker
	fmt.Printf("\nTest 2: Second attempt (should be blocked by circuit breaker)...\n")
	start = time.Now()
	
	result2 := protocol.DecryptXORWithClientAddr(fullData, clientAddr)
	duration2 := time.Since(start)
	
	fmt.Printf("Second attempt took: %v\n", duration2)
	fmt.Printf("Result length: %d bytes\n", len(result2))
	
	if duration2 > 1*time.Second {
		fmt.Printf("❌ FAIL: Second attempt took too long (%v), expected < 1s (circuit breaker)\n", duration2)
	} else {
		fmt.Printf("✅ PASS: Second attempt was fast (%v) - circuit breaker working\n", duration2)
	}

	// Test 3: Test with known user data (should be fast)
	fmt.Printf("\nTest 3: Known user data (should be fast)...\n")
	knownUserData := []byte{
		// This is encrypted with the first known key (admin user)
		0x45, 0x73, 0x77, 0x29, 0x2f, 0xda, 0x9a, 0x21, 0x10, 0x52, 0xb1, 0x9c, 0x70, 0x93, 0x0e, 0xa0,
		0x61, 0x64, 0x6d, 0x69, 0x6e, 0x00, // "admin" XORed
		0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00, // password part
	}
	
	start = time.Now()
	result3 := protocol.DecryptXORWithClientAddr(knownUserData, "127.0.0.1:54321")
	duration3 := time.Since(start)
	
	fmt.Printf("Known user attempt took: %v\n", duration3)
	fmt.Printf("Result: %q\n", string(result3))
	
	if duration3 > 1*time.Second {
		fmt.Printf("❌ FAIL: Known user attempt took too long (%v), expected < 1s\n", duration3)
	} else {
		fmt.Printf("✅ PASS: Known user attempt was fast (%v)\n", duration3)
	}

	fmt.Printf("\nTimeout fix test completed!\n")
}