package main

import (
	"fmt"
	"log"
	"os"
	
	"jx2-paysys/internal/protocol"
)

func main() {
	fmt.Println("=== Testing Bishop Protocol Format Fix ===")
	
	// Suppress debug logs for cleaner output
	log.SetOutput(os.Stderr)
	
	// Simulate the exact tester_3 data that was causing timeout
	bishopProtocolData := []byte{
		// First 32 bytes: XOR key repeated twice (ad692ba79d670c500ea5aec317fba5ad twice)
		0xad, 0x69, 0x2b, 0xa7, 0x9d, 0x67, 0x0c, 0x50, 0x0e, 0xa5, 0xae, 0xc3, 0x17, 0xfb, 0xa5, 0xad,
		0xad, 0x69, 0x2b, 0xa7, 0x9d, 0x67, 0x0c, 0x50, 0x0e, 0xa5, 0xae, 0xc3, 0x17, 0xfb, 0xa5, 0xad,
		// After byte 32: Plain text login data "tester_3\0MD5_HASH"
		0x74, 0x65, 0x73, 0x74, 0x65, 0x72, 0x5f, 0x33, 0x00, 0x35, 0x44, 0x34, 0x31, 0x34, 0x30, 0x32,
		0x41, 0x42, 0x43, 0x34, 0x42, 0x32, 0x41, 0x37, 0x36, 0x42, 0x39, 0x37, 0x31, 0x39, 0x44, 0x39,
		0x31, 0x31, 0x30, 0x31, 0x37, 0x43, 0x35, 0x39, 0x32, // Complete MD5 hash
	}
	
	fmt.Printf("Testing with %d bytes of Bishop protocol data\n", len(bishopProtocolData))
	
	// Test the new DecryptXORFast function
	result := protocol.DecryptXORFast(bishopProtocolData, "tester_3_client")
	
	if result != nil {
		fmt.Printf("✅ DecryptXORFast succeeded (%d bytes)\n", len(result))
		fmt.Printf("Decrypted data: %x\n", result)
		fmt.Printf("As text: %q\n", string(result))
		
		// Test parsing
		username, password, err := protocol.ParseLoginDataFast(result)
		if err != nil {
			fmt.Printf("❌ ParseLoginDataFast failed: %v\n", err)
		} else {
			fmt.Printf("✅ Parsed successfully - Username: %q, Password: %q\n", username, password)
			
			if username == "tester_3" {
				fmt.Println("✅ Username matches expected tester_3")
				fmt.Println("✅ This should now authenticate properly instead of returning immediate success")
			} else {
				fmt.Printf("❌ Username mismatch: got %q, expected tester_3\n", username)
			}
		}
	} else {
		fmt.Println("❌ DecryptXORFast failed - this means the fix didn't work")
	}
}