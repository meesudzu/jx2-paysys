package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"jx2-paysys/internal/protocol"
)

func main() {
	log.SetOutput(os.Stdout)
	log.Printf("=== Testing Dynamic User Support (No Fixed Keys) ===")

	// Test 1: Completely new user with random key
	log.Printf("\n--- Test 1: New User with Random Key ---")
	testRandomKeyUser()

	// Test 2: User with algorithmic key pattern
	log.Printf("\n--- Test 2: User with Algorithmic Key ---")
	testAlgorithmicKeyUser()

	// Test 3: Multiple new users with different keys
	log.Printf("\n--- Test 3: Multiple Different Users ---")
	testMultipleNewUsers()

	// Test 4: Key learning and reuse
	log.Printf("\n--- Test 4: Key Learning and Reuse ---")
	testKeyLearningReuse()

	log.Printf("\n=== All Dynamic User Tests Completed ===")
}

func testRandomKeyUser() {
	// Generate a completely random 16-byte XOR key
	randomKey := []byte{0x7F, 0x3E, 0x91, 0xC4, 0x56, 0x82, 0xA7, 0x15, 0xB9, 0x68, 0xD3, 0x47, 0x92, 0x05, 0xCE, 0x74}
	
	// Create sample login data
	loginData := createSampleLoginData("randomuser", "password123")
	
	// Encrypt with the random key
	encryptedData := xorEncrypt(loginData, randomKey)
	
	log.Printf("Original key: %x", randomKey)
	log.Printf("Encrypted data: %x", encryptedData)
	
	// Try to decrypt with dynamic detection
	start := time.Now()
	decryptedData := protocol.DecryptXOR(encryptedData)
	elapsed := time.Since(start)
	
	log.Printf("Decrypted data: %x", decryptedData)
	log.Printf("Decryption time: %v", elapsed)
	
	// Parse the decrypted data
	username, password, err := protocol.ParseLoginData(decryptedData)
	if err != nil {
		log.Printf("❌ Failed to parse login data: %v", err)
	} else {
		log.Printf("✅ Successfully extracted - Username: %s, Password: %s", username, password)
	}
}

func testAlgorithmicKeyUser() {
	// Generate a key using a simple algorithm
	algorithmicKey := make([]byte, 16)
	for i := 0; i < 16; i++ {
		algorithmicKey[i] = byte((i * 17 + 42) % 256) // Simple pattern
	}
	
	// Create sample login data
	loginData := createSampleLoginData("algouser", "mypassword")
	
	// Encrypt with the algorithmic key
	encryptedData := xorEncrypt(loginData, algorithmicKey)
	
	log.Printf("Algorithmic key: %x", algorithmicKey)
	log.Printf("Encrypted data: %x", encryptedData)
	
	// Try to decrypt with dynamic detection
	start := time.Now()
	decryptedData := protocol.DecryptXOR(encryptedData)
	elapsed := time.Since(start)
	
	log.Printf("Decrypted data: %x", decryptedData)
	log.Printf("Decryption time: %v", elapsed)
	
	// Parse the decrypted data
	username, password, err := protocol.ParseLoginData(decryptedData)
	if err != nil {
		log.Printf("❌ Failed to parse login data: %v", err)
	} else {
		log.Printf("✅ Successfully extracted - Username: %s, Password: %s", username, password)
	}
}

func testMultipleNewUsers() {
	users := []struct {
		username string
		password string
		key      []byte
	}{
		{"user1", "pass1", []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00}},
		{"user2", "pass2", []byte{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00}},
		{"user3", "pass3", []byte{0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
	}
	
	for i, user := range users {
		log.Printf("Testing user %d: %s", i+1, user.username)
		
		// Create and encrypt login data
		loginData := createSampleLoginData(user.username, user.password)
		encryptedData := xorEncrypt(loginData, user.key)
		
		// Try dynamic decryption
		start := time.Now()
		decryptedData := protocol.DecryptXOR(encryptedData)
		elapsed := time.Since(start)
		
		// Parse results
		username, password, err := protocol.ParseLoginData(decryptedData)
		if err != nil {
			log.Printf("❌ User %d failed: %v", i+1, err)
		} else {
			log.Printf("✅ User %d success - Username: %s, Password: %s (time: %v)", i+1, username, password, elapsed)
		}
	}
}

func testKeyLearningReuse() {
	// Create a user with a specific key
	username := "learninguser"
	password := "learnpass"
	userKey := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	
	log.Printf("Testing key learning for user: %s", username)
	log.Printf("User key: %x", userKey)
	
	// First login - should learn the key
	loginData1 := createSampleLoginData(username, password)
	encryptedData1 := xorEncrypt(loginData1, userKey)
	
	log.Printf("First login attempt...")
	start := time.Now()
	decryptedData1, usedKey := protocol.DecryptXORWithUsername(encryptedData1, username)
	elapsed1 := time.Since(start)
	
	username1, password1, err1 := protocol.ParseLoginData(decryptedData1)
	if err1 != nil {
		log.Printf("❌ First login failed: %v", err1)
	} else {
		log.Printf("✅ First login success - Username: %s, Password: %s (time: %v)", username1, password1, elapsed1)
		if len(usedKey) == 16 {
			log.Printf("Key learned: %x", usedKey)
		}
	}
	
	// Second login - should use learned key (faster)
	loginData2 := createSampleLoginData(username, password+"2")
	encryptedData2 := xorEncrypt(loginData2, userKey)
	
	log.Printf("Second login attempt (should be faster)...")
	start = time.Now()
	decryptedData2, usedKey2 := protocol.DecryptXORWithUsername(encryptedData2, username)
	elapsed2 := time.Since(start)
	
	username2, password2, err2 := protocol.ParseLoginData(decryptedData2)
	if err2 != nil {
		log.Printf("❌ Second login failed: %v", err2)
	} else {
		log.Printf("✅ Second login success - Username: %s, Password: %s (time: %v)", username2, password2, elapsed2)
		if len(usedKey2) == 16 {
			log.Printf("Key reused: %x", usedKey2)
		}
	}
	
	// Compare performance
	if elapsed2 < elapsed1 {
		log.Printf("✅ Key learning improved performance: %v -> %v", elapsed1, elapsed2)
	} else {
		log.Printf("⚠️  Key learning did not improve performance: %v -> %v", elapsed1, elapsed2)
	}
}

// Helper function to create sample login data
func createSampleLoginData(username, password string) []byte {
	// Create a simple login packet structure
	// This mimics the format that would be seen in real JX2 packets
	data := make([]byte, 0, 256)
	
	// Simple header
	data = append(data, 0x00, 0x0A, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00)
	
	// Username (null-terminated)
	data = append(data, []byte(username)...)
	data = append(data, 0x00)
	
	// Padding to align password
	for len(data) < 45 {
		data = append(data, 0x00)
	}
	
	// Password (MD5 hash format)
	if len(password) == 32 {
		data = append(data, []byte(password)...)
	} else {
		// Convert to uppercase hex-like string for testing
		md5like := fmt.Sprintf("%032X", []byte(password))
		if len(md5like) > 32 {
			md5like = md5like[:32]
		}
		data = append(data, []byte(md5like)...)
	}
	
	// Null terminator
	data = append(data, 0x00)
	
	// Pad to reasonable size
	for len(data) < 128 {
		data = append(data, 0x00)
	}
	
	return data
}

// Helper function to XOR encrypt data
func xorEncrypt(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}