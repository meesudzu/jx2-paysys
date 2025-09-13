package main

import (
	"fmt"
	"time"
	"jx2-paysys/internal/protocol"
)

// Simulate a new user with an unknown XOR key
func testNewUserScenario() {
	fmt.Println("=== Testing New User XOR Key Support ===")
	
	// Simulate a new user "newuser" with a completely unknown XOR key
	// For this test, we'll use a new pattern that's not in the known keys
	newUserKey := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}
	
	// Create sample login data that would be sent by a new user
	loginData := []byte{
		0x00, 0x0A, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, // Header
		'n', 'e', 'w', 'u', 's', 'e', 'r', 0x00, // Username "newuser"
	}
	
	// Pad to password area (offset 45)
	for len(loginData) < 45 {
		loginData = append(loginData, 0x00)
	}
	
	// Add MD5 password hash
	password := "5D41402ABC4B2A76B9719D911017C592" // MD5 of "hello"
	loginData = append(loginData, []byte(password)...)
	
	// Pad to full size
	for len(loginData) < 224 {
		loginData = append(loginData, 0x00)
	}
	
	// Encrypt with the new user's key
	encryptedData := make([]byte, len(loginData))
	for i := 0; i < len(loginData); i++ {
		encryptedData[i] = loginData[i] ^ newUserKey[i%len(newUserKey)]
	}
	
	fmt.Printf("Simulated encrypted login data for new user: %x...\n", encryptedData[:32])
	
	// Test 1: Regular decryption (should not work well with unknown key)
	fmt.Println("\n--- Test 1: Regular DecryptXOR (without username) ---")
	decrypted1 := protocol.DecryptXOR(encryptedData)
	username1, password1, err1 := protocol.ParseLoginData(decrypted1)
	fmt.Printf("Result: username='%s', password='%s', error=%v\n", username1, password1, err1)
	
	// Test 2: Username-aware decryption (should learn the key)
	fmt.Println("\n--- Test 2: DecryptXORWithUsername (should learn key) ---")
	decrypted2, learnedKey := protocol.DecryptXORWithUsername(encryptedData, "newuser")
	username2, password2, err2 := protocol.ParseLoginData(decrypted2)
	fmt.Printf("Result: username='%s', password='%s', error=%v\n", username2, password2, err2)
	if learnedKey != nil {
		fmt.Printf("Learned key: %x\n", learnedKey)
	}
	
	// Test 3: Second login attempt (should use learned key)
	fmt.Println("\n--- Test 3: Second login (should use learned key) ---")
	decrypted3, usedKey := protocol.DecryptXORWithUsername(encryptedData, "newuser")
	username3, password3, err3 := protocol.ParseLoginData(decrypted3)
	fmt.Printf("Result: username='%s', password='%s', error=%v\n", username3, password3, err3)
	if usedKey != nil {
		fmt.Printf("Used key: %x\n", usedKey)
	}
	
	fmt.Println("\n=== Test Complete ===")
	
	// Wait a moment for the save goroutine to complete
	time.Sleep(100 * time.Millisecond)
	
	// Check if the key was saved
	fmt.Println("\n--- Checking saved keys ---")
	fmt.Println("Checking /tmp/learned_keys.txt...")
}

func main() {
	testNewUserScenario()
}