package main

import (
	"encoding/hex"
	"fmt"
	"jx2-paysys/internal/protocol"
)

func main() {
	fmt.Println("=== Testing Enhanced XOR Decryption ===")
	
	// Test 1: Original admin packet (should still work)
	fmt.Println("\nTest 1: Original admin packet")
	originalPayload, _ := hex.DecodeString("4579772b2fdb9a211033d5f119fd0ea0457377292fda9a211052b19c70930ea0")
	decrypted1 := protocol.DecryptXOR(originalPayload)
	username1, password1, err1 := protocol.ParseLoginData(decrypted1)
	
	fmt.Printf("Original payload: %x\n", originalPayload[:32])
	fmt.Printf("Decrypted: %x\n", decrypted1[:32])
	fmt.Printf("Username: '%s', Password: '%s', Error: %v\n", username1, password1, err1)
	
	// Test 2: New tester packet
	fmt.Println("\nTest 2: New tester packet")
	newPayload, _ := hex.DecodeString("f5207b17fbb6adad692ba79d670c500ea5aec317fba5adad692ba79d670c500ea5aec317fba5adad692aa79d670c700ea5aec317fba575b2692ba79d670c540ea5aec317fba5adad692ba79d670c510ea5aec317fba5acad692ba79d670c500ea5aec317fba5adad692ba79d670c510ea5aec317fb583c6d682ba79d670c5809a52e7b68fba5a5aa69ab1fe2670c2041a52ec368fba5dde269ab1fe2670c500ea5aec317c1")
	decrypted2 := protocol.DecryptXOR(newPayload)
	username2, password2, err2 := protocol.ParseLoginData(decrypted2)
	
	fmt.Printf("New payload: %x\n", newPayload[:32])
	fmt.Printf("Decrypted: %x\n", decrypted2[:32])
	fmt.Printf("Username: '%s', Password: '%s', Error: %v\n", username2, password2, err2)
}