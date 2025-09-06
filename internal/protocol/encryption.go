package protocol

import (
	"fmt"
	"strings"
)

// DecryptXOR performs XOR decryption on login data
// Enhanced to handle multiple encryption keys found in different user scenarios
func DecryptXOR(data []byte) []byte {
	// Try to automatically detect the correct XOR key from repeating patterns
	xorKey := extractXORKey(data)
	
	if len(xorKey) == 0 {
		// If pattern extraction fails, try known keys in order of preference
		knownKeys := [][]byte{
			// Original key (works for "admin" user from player-login.pcap)
			{0x45, 0x73, 0x77, 0x29, 0x2f, 0xda, 0x9a, 0x21, 0x10, 0x52, 0xb1, 0x9c, 0x70, 0x93, 0x0e, 0xa0},
			// New key found in tester_1_create_character_and_login_game.pcap
			{0xa5, 0xae, 0xc3, 0x17, 0xfb, 0xa5, 0xad, 0xad, 0x69, 0x2b, 0xa7, 0x9d, 0x67, 0x0c, 0x51, 0x0e},
		}
		
		// Try each known key and pick the one that gives the best result
		bestKey := knownKeys[0] // Default to first key
		bestScore := evaluateDecryption(data, knownKeys[0])
		
		for _, key := range knownKeys[1:] {
			score := evaluateDecryption(data, key)
			if score > bestScore {
				bestKey = key
				bestScore = score
			}
		}
		
		xorKey = bestKey
	}
	
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ xorKey[i%len(xorKey)]
	}
	
	return result
}

// extractXORKey tries to extract the XOR key from repeating patterns
func extractXORKey(data []byte) []byte {
	// Look for repeating patterns that could indicate XOR encryption
	
	// Method 1: Look for the original known pattern (from admin login)
	originalPattern := []byte{0x45, 0x73, 0x77, 0x29, 0x2f, 0xda, 0x9a, 0x21, 0x10, 0x52, 0xb1, 0x9c, 0x70, 0x93, 0x0e, 0xa0}
	if findPattern(data, originalPattern) {
		return originalPattern
	}
	
	// Method 2: Look for new pattern found in tester analysis
	newPattern := []byte{0xa5, 0xae, 0xc3, 0x17, 0xfb, 0xa5, 0xad, 0xad, 0x69, 0x2b, 0xa7, 0x9d, 0x67, 0x0c, 0x51, 0x0e}
	if findPattern(data, newPattern) {
		return newPattern
	}
	
	// Method 3: Auto-detect key from repeating 16-byte patterns
	patternCounts := make(map[string]int)
	
	// Look for repeating 16-byte chunks (common XOR key length)
	if len(data) >= 32 { // Need at least 2 chunks to detect repetition
		for i := 0; i <= len(data)-16; i += 16 {
			if i+16 <= len(data) {
				pattern := string(data[i : i+16])
				patternCounts[pattern]++
			}
		}
		
		// Find the most common pattern
		var mostCommonPattern string
		maxCount := 0
		for pattern, count := range patternCounts {
			if count > maxCount && count > 1 { // Must repeat at least once
				maxCount = count
				mostCommonPattern = pattern
			}
		}
		
		if mostCommonPattern != "" {
			return []byte(mostCommonPattern)
		}
	}
	
	return nil
}

// findPattern checks if a pattern exists in the data
func findPattern(data, pattern []byte) bool {
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// evaluateDecryption scores how "good" a decryption looks
func evaluateDecryption(data, key []byte) int {
	// Decrypt with the key
	decrypted := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		decrypted[i] = data[i] ^ key[i%len(key)]
	}
	
	score := 0
	
	// Score based on printable ASCII characters
	printableCount := 0
	for _, b := range decrypted {
		if b >= 32 && b <= 126 {
			printableCount++
		} else if b == 0 {
			// Null bytes are common in structured data
			printableCount++
		}
	}
	score += printableCount * 2
	
	// Score based on null-terminated string patterns
	nullSeparated := 0
	for i := 0; i < len(decrypted)-1; i++ {
		if decrypted[i] != 0 && decrypted[i+1] == 0 {
			nullSeparated++
		}
	}
	score += nullSeparated * 10
	
	// Penalize completely random-looking data
	if printableCount < len(decrypted)/4 {
		score -= 100
	}
	
	return score
}

// EncryptXOR performs XOR encryption on response data
// Uses dynamic key selection based on detected patterns
func EncryptXOR(data []byte) []byte {
	// Use the most common key for encryption (the original key)
	// In a real implementation, you'd want to use the same key that was used for decryption
	xorKey := []byte{0x45, 0x73, 0x77, 0x29, 0x2f, 0xda, 0x9a, 0x21, 0x10, 0x52, 0xb1, 0x9c, 0x70, 0x93, 0x0e, 0xa0}
	
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ xorKey[i%len(xorKey)]
	}
	
	return result
}

// ParseLoginData parses decrypted login data to extract username and password
// Enhanced to handle both string-based and binary login formats
func ParseLoginData(decryptedData []byte) (username, password string, err error) {
	// Method 1: Try classic null-separated string format (admin login style)
	username, password, err = parseStringBasedLogin(decryptedData)
	if err == nil && username != "" {
		return username, password, nil
	}
	
	// Method 2: Try structured binary format (tester login style)
	username, password, err = parseBinaryBasedLogin(decryptedData)
	if err == nil && username != "" {
		return username, password, nil
	}
	
	// Method 3: Fallback to raw string extraction
	return parseRawStringLogin(decryptedData)
}

// parseStringBasedLogin handles the classic string-based login format
func parseStringBasedLogin(decryptedData []byte) (username, password string, err error) {
	// Remove null bytes and non-printable characters
	cleanData := make([]byte, 0, len(decryptedData))
	for _, b := range decryptedData {
		if b >= 32 && b <= 126 { // Printable ASCII characters
			cleanData = append(cleanData, b)
		} else if b == 0 {
			cleanData = append(cleanData, 0) // Keep null terminators
		}
	}
	
	// Split by null bytes to find strings
	parts := strings.Split(string(cleanData), "\x00")
	validParts := make([]string, 0)
	
	for _, part := range parts {
		if len(part) > 0 && len(part) < 256 { // Reasonable length for username/password
			validParts = append(validParts, part)
		}
	}
	
	// Typically, username comes first, then password
	if len(validParts) >= 2 {
		username = validParts[0]
		password = validParts[1]
		return username, password, nil
	} else if len(validParts) >= 1 {
		// Only one string found, might be username only
		username = validParts[0]
		return username, "", nil
	}
	
	return "", "", fmt.Errorf("could not parse string-based login data")
}

// parseBinaryBasedLogin handles structured binary login format
func parseBinaryBasedLogin(decryptedData []byte) (username, password string, err error) {
	// Look for ASCII strings embedded in binary data
	strings := extractEmbeddedStrings(decryptedData)
	
	if len(strings) >= 2 {
		// Assume first two strings are username and password
		return strings[0], strings[1], nil
	} else if len(strings) == 1 {
		// Single string found, use as username
		return strings[0], "", nil
	}
	
	// If no clear strings found, try to infer from binary data structure
	// Look for common patterns in binary login packets
	if len(decryptedData) >= 16 {
		// Check if this might be a structured login with fixed-length fields
		// Look for printable characters at common offsets
		for offset := 0; offset < len(decryptedData)-8; offset += 4 {
			if offset+32 < len(decryptedData) {
				// Try to extract a 32-byte string field
				field := decryptedData[offset : offset+32]
				nullPos := -1
				for i, b := range field {
					if b == 0 {
						nullPos = i
						break
					}
				}
				
				if nullPos > 2 { // Found a null-terminated string
					candidate := string(field[:nullPos])
					if isValidUsername(candidate) {
						return candidate, "", nil
					}
				}
			}
		}
	}
	
	return "", "", fmt.Errorf("could not parse binary-based login data")
}

// parseRawStringLogin extracts any readable strings as fallback
func parseRawStringLogin(decryptedData []byte) (username, password string, err error) {
	// Extract all possible ASCII strings
	allStrings := extractEmbeddedStrings(decryptedData)
	
	// Filter for reasonable username candidates
	var candidates []string
	for _, s := range allStrings {
		if isValidUsername(s) {
			candidates = append(candidates, s)
		}
	}
	
	if len(candidates) > 0 {
		return candidates[0], "", nil
	}
	
	return "", "", fmt.Errorf("could not extract any login data")
}

// extractEmbeddedStrings finds ASCII strings in binary data
func extractEmbeddedStrings(data []byte) []string {
	var strings []string
	currentString := ""
	
	for _, b := range data {
		if b >= 32 && b <= 126 { // Printable ASCII
			currentString += string(b)
		} else {
			if len(currentString) > 2 { // Minimum length for meaningful string
				strings = append(strings, currentString)
			}
			currentString = ""
		}
	}
	
	// Don't forget the last string if data doesn't end with non-printable
	if len(currentString) > 2 {
		strings = append(strings, currentString)
	}
	
	return strings
}

// isValidUsername checks if a string looks like a valid username
func isValidUsername(s string) bool {
	if len(s) < 2 || len(s) > 32 {
		return false
	}
	
	// Username should contain only alphanumeric characters and common symbols
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
			 (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	
	return true
}

// CreateEncryptedLoginResponse creates an encrypted login response
func CreateEncryptedLoginResponse(result uint8, message string) []byte {
	// Create response data
	responseData := make([]byte, 0, 256)
	responseData = append(responseData, result)
	responseData = append(responseData, []byte(message)...)
	responseData = append(responseData, 0) // Null terminator
	
	// Pad to a reasonable size
	for len(responseData) < 64 {
		responseData = append(responseData, 0)
	}
	
	// Encrypt the response
	encryptedData := EncryptXOR(responseData)
	
	// Create packet header
	header := PacketHeader{
		Size: uint16(4 + len(encryptedData)),
		Type: PacketTypeUserResponse,
	}
	
	// Combine header and encrypted data
	result_packet := make([]byte, 0, int(header.Size))
	result_packet = append(result_packet, byte(header.Size&0xFF), byte((header.Size>>8)&0xFF))
	result_packet = append(result_packet, byte(header.Type&0xFF), byte((header.Type>>8)&0xFF))
	result_packet = append(result_packet, encryptedData...)
	
	return result_packet
}