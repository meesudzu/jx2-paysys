package main

import (
	"fmt"
	"time"

	"jx2-paysys/internal/protocol"
)

func main() {
	fmt.Println("Testing comprehensive login hang fix...")

	// Test scenarios that could cause hanging

	// Scenario 1: Completely random data (worst case for key detection)
	fmt.Println("\n=== Scenario 1: Random data (should trigger circuit breaker quickly) ===")
	randomData := make([]byte, 225)
	for i := range randomData {
		randomData[i] = byte(i % 256)
	}
	
	start := time.Now()
	result1 := protocol.DecryptXORWithClientAddr(randomData, "test-client-1")
	duration1 := time.Since(start)
	fmt.Printf("Random data test took: %v\n", duration1)
	fmt.Printf("Result length: %d bytes\n", len(result1))
	
	if duration1 > 15*time.Second {
		fmt.Printf("❌ FAIL: Random data test took too long (%v)\n", duration1)
	} else {
		fmt.Printf("✅ PASS: Random data test completed quickly (%v)\n", duration1)
	}

	// Scenario 2: Malformed login data (could cause parsing issues)
	fmt.Println("\n=== Scenario 2: Malformed login data ===")
	malformedData := make([]byte, 225)
	// Fill with repeating pattern that might confuse parser
	pattern := []byte{0xFF, 0x00, 0xFF, 0x00, 0x41, 0x41, 0x41}
	for i := range malformedData {
		malformedData[i] = pattern[i%len(pattern)]
	}
	
	start = time.Now()
	decrypted := protocol.DecryptXORWithClientAddr(malformedData, "test-client-2")
	_, _, err := protocol.ParseLoginData(decrypted)
	duration2 := time.Since(start)
	
	fmt.Printf("Malformed data parsing took: %v\n", duration2)
	fmt.Printf("Parse error (expected): %v\n", err)
	
	if duration2 > 10*time.Second {
		fmt.Printf("❌ FAIL: Malformed data parsing took too long (%v)\n", duration2)
	} else {
		fmt.Printf("✅ PASS: Malformed data parsing completed quickly (%v)\n", duration2)
	}

	// Scenario 3: Very large data (memory/processing issue)
	fmt.Println("\n=== Scenario 3: Large data test ===")
	largeData := make([]byte, 1024) // Much larger than typical
	for i := range largeData {
		largeData[i] = byte((i*7 + 13) % 256)
	}
	
	start = time.Now()
	result3 := protocol.DecryptXORWithClientAddr(largeData, "test-client-3")
	duration3 := time.Since(start)
	
	fmt.Printf("Large data test took: %v\n", duration3)
	fmt.Printf("Result length: %d bytes\n", len(result3))
	
	if duration3 > 15*time.Second {
		fmt.Printf("❌ FAIL: Large data test took too long (%v)\n", duration3)
	} else {
		fmt.Printf("✅ PASS: Large data test completed quickly (%v)\n", duration3)
	}

	// Scenario 4: Rapid multiple requests (stress test)
	fmt.Println("\n=== Scenario 4: Rapid multiple requests ===")
	start = time.Now()
	for i := 0; i < 10; i++ {
		testData := make([]byte, 100)
		for j := range testData {
			testData[j] = byte((i*j + 42) % 256)
		}
		result := protocol.DecryptXORWithClientAddr(testData, fmt.Sprintf("stress-client-%d", i))
		if len(result) == 0 {
			fmt.Printf("Empty result for stress test %d\n", i)
		}
	}
	duration4 := time.Since(start)
	
	fmt.Printf("10 rapid requests took: %v\n", duration4)
	
	if duration4 > 30*time.Second {
		fmt.Printf("❌ FAIL: Rapid requests took too long (%v)\n", duration4)
	} else {
		fmt.Printf("✅ PASS: Rapid requests completed quickly (%v)\n", duration4)
	}

	// Scenario 5: Null bytes and edge cases
	fmt.Println("\n=== Scenario 5: Edge case data ===")
	edgeCaseData := make([]byte, 225)
	// Mix of nulls, high values, and patterns that might confuse parsers
	patterns := [][]byte{
		{0x00, 0x00, 0x00, 0x00},
		{0xFF, 0xFF, 0xFF, 0xFF},
		{0x41, 0x42, 0x43, 0x00}, // ABC\0
		{0x20, 0x20, 0x20, 0x20}, // spaces
	}
	
	for i := range edgeCaseData {
		pattern := patterns[i%len(patterns)]
		edgeCaseData[i] = pattern[i%len(pattern)]
	}
	
	start = time.Now()
	result5 := protocol.DecryptXORWithClientAddr(edgeCaseData, "edge-case-client")
	_, _, err5 := protocol.ParseLoginData(result5)
	duration5 := time.Since(start)
	
	fmt.Printf("Edge case test took: %v\n", duration5)
	fmt.Printf("Parse result: %v\n", err5)
	
	if duration5 > 10*time.Second {
		fmt.Printf("❌ FAIL: Edge case test took too long (%v)\n", duration5)
	} else {
		fmt.Printf("✅ PASS: Edge case test completed quickly (%v)\n", duration5)
	}

	// Summary
	fmt.Println("\n=== SUMMARY ===")
	totalTime := duration1 + duration2 + duration3 + duration4 + duration5
	fmt.Printf("Total time for all tests: %v\n", totalTime)
	
	if totalTime > 60*time.Second {
		fmt.Printf("❌ OVERALL FAIL: Total time too long (%v)\n", totalTime)
	} else {
		fmt.Printf("✅ OVERALL PASS: All tests completed within reasonable time (%v)\n", totalTime)
	}
	
	fmt.Println("\nLogin hang fix test completed!")
	fmt.Println("If this completes quickly (< 1 minute total), the hang issue should be resolved.")
}