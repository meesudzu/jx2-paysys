package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	"jx2-paysys/internal/protocol"
)

func main() {
	fmt.Println("=== JX2 Paysys Protocol Test ===")
	
	// Test packet parsing with real PCAP data
	testBishopLogin()
	testPlayerLogin()
}

func testBishopLogin() {
	fmt.Println("\n--- Testing Bishop Login Packet ---")
	
	// Bishop login packet from PCAP
	bishopData := "22002000000000000000f54d3fc95acfb25e00000000000000000000000000000000"
	data, err := hex.DecodeString(bishopData)
	if err != nil {
		log.Printf("Error decoding bishop data: %v", err)
		return
	}
	
	fmt.Printf("Raw packet (%d bytes): %x\n", len(data), data)
	
	packet, err := protocol.ParsePacket(data)
	if err != nil {
		log.Printf("Error parsing bishop packet: %v", err)
		return
	}
	
	if bishopPacket, ok := packet.(*protocol.BishopLoginPacket); ok {
		fmt.Printf("Packet Type: 0x%04X\n", bishopPacket.Header.Type)
		fmt.Printf("Packet Size: %d\n", bishopPacket.Header.Size)
		fmt.Printf("Unknown1: 0x%08X\n", bishopPacket.Unknown1)
		fmt.Printf("Unknown2: 0x%08X\n", bishopPacket.Unknown2)
		fmt.Printf("Unknown3: 0x%08X\n", bishopPacket.Unknown3)
		fmt.Printf("Bishop ID: %x\n", bishopPacket.BishopID)
		
		// Test response creation
		response := protocol.CreateBishopResponse(0)
		fmt.Printf("Response packet: %x\n", response)
	}
}

func testPlayerLogin() {
	fmt.Println("\n--- Testing Player Login Packet ---")
	
	// Player login packet from PCAP (first part)
	playerData := "e500ff424579772b2fdb9a211033d5f119fd0ea0457377292fda9a211052b19c70930ea0457377292fda9a21101185df31a73c937d32476b16e8a9192262f5df33a63e990445311e1ae2ae185252b19c70930ea0457377292fda9a211052b19c70930ea0457377292fda9a21109219ad714030a04530cba0954552247669a55d2284ae1d3b7377292fda9a211052b19c70930ea0457377292fda9a211052b19c70930ea0457377292fda9a211052b19c7093ca91c774270481f986480a2d9979b6930ea0457377292fda9a211052b19c70930ea0457377292fda9a211052b19c70930ea0c1"
	data, err := hex.DecodeString(playerData)
	if err != nil {
		log.Printf("Error decoding player data: %v", err)
		return
	}
	
	fmt.Printf("Raw packet (%d bytes): %x\n", len(data), data)
	
	packet, err := protocol.ParsePacket(data)
	if err != nil {
		log.Printf("Error parsing player packet: %v", err)
		return
	}
	
	if playerPacket, ok := packet.(*protocol.UserLoginPacket); ok {
		fmt.Printf("Packet Type: 0x%04X\n", playerPacket.Header.Type)
		fmt.Printf("Packet Size: %d\n", playerPacket.Header.Size)
		fmt.Printf("Encrypted Data (%d bytes): %x\n", len(playerPacket.EncryptedData), playerPacket.EncryptedData)
		
		// Test decryption
		decryptedData := protocol.DecryptXOR(playerPacket.EncryptedData)
		fmt.Printf("Decrypted Data: %x\n", decryptedData)
		fmt.Printf("Decrypted as string: %q\n", string(decryptedData))
		
		// Try to parse login data
		username, password, err := protocol.ParseLoginData(decryptedData)
		if err != nil {
			fmt.Printf("Error parsing login data: %v\n", err)
		} else {
			fmt.Printf("Parsed - Username: %q, Password: %q\n", username, password)
		}
		
		// Test response creation
		response := protocol.CreateEncryptedLoginResponse(0, "Login successful")
		fmt.Printf("Response packet (%d bytes): %x\n", len(response), response)
	}
}

// testServerConnection tests connecting to a running server
func testServerConnection() {
	fmt.Println("\n--- Testing Server Connection ---")
	
	// Connect to the server
	conn, err := net.DialTimeout("tcp", "127.0.0.1:8000", 5*time.Second)
	if err != nil {
		log.Printf("Failed to connect to server: %v", err)
		return
	}
	defer conn.Close()
	
	// Send bishop login packet
	bishopData := "22002000000000000000f54d3fc95acfb25e00000000000000000000000000000000"
	data, _ := hex.DecodeString(bishopData)
	
	_, err = conn.Write(data)
	if err != nil {
		log.Printf("Failed to send data: %v", err)
		return
	}
	
	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		log.Printf("Failed to read response: %v", err)
		return
	}
	
	fmt.Printf("Server response (%d bytes): %x\n", n, response[:n])
}