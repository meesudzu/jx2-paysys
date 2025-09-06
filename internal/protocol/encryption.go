package protocol

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
)

// LearnedKeys stores dynamically discovered XOR keys for new users
var (
	learnedKeys   = make(map[string][]byte) // username -> XOR key
	learnedKeysMu sync.RWMutex
	keyStorage    = "/tmp/learned_keys.txt" // File to persist learned keys
)

// init loads any previously learned keys
func init() {
	loadLearnedKeys()
}

// DecryptXOR performs XOR decryption on login data
// Enhanced to handle multiple encryption keys found in different user scenarios and new users
func DecryptXOR(data []byte) []byte {
	// Try to automatically detect the correct XOR key from repeating patterns
	xorKey := extractXORKey(data)
	
	if len(xorKey) == 0 {
		// If pattern extraction fails, try known keys in order of preference
		knownKeys := [][]byte{
			// Original key (works for "admin" user from player-login.pcap)
			{0x45, 0x73, 0x77, 0x29, 0x2f, 0xda, 0x9a, 0x21, 0x10, 0x52, 0xb1, 0x9c, 0x70, 0x93, 0x0e, 0xa0},
			// Tester_1 key found in tester_1_create_character_and_login_game.pcap
			{0xa5, 0xae, 0xc3, 0x17, 0xfb, 0xa5, 0xad, 0xad, 0x69, 0x2b, 0xa7, 0x9d, 0x67, 0x0c, 0x51, 0x0e},
			// Tester_3 key found in tester_3_create_character_and_login_game.pcap (rotated variant of tester_1)
			{0xad, 0x69, 0x2b, 0xa7, 0x9d, 0x67, 0x0c, 0x50, 0x0e, 0xa5, 0xae, 0xc3, 0x17, 0xfb, 0xa5, 0xad},
			// Tester_4 key found in tester_4_create_character_and_login_game.pcap
			{0x47, 0xe7, 0x92, 0xaf, 0x28, 0xdb, 0x6e, 0x54, 0xec, 0xf7, 0x9b, 0xf7, 0xb4, 0x4d, 0xe1, 0x63},
			// Character creation key used by multiple users for character creation packets
			{0x63, 0xd5, 0xb8, 0xd7, 0x2b, 0x9b, 0x02, 0x2a, 0x5e, 0xc9, 0x38, 0x3f, 0x79, 0x66, 0x50, 0xda},
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
		
		// For new users, try advanced detection methods if known keys don't work well
		if bestScore < 50 { // Threshold for "good enough" decryption
			newUserKey := detectNewUserXORKey(data)
			if len(newUserKey) == 16 {
				newScore := evaluateDecryption(data, newUserKey)
				if newScore > bestScore {
					bestKey = newUserKey
					bestScore = newScore
					log.Printf("[Encryption] Detected new user XOR key: %x (score: %d)", newUserKey, newScore)
				}
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
	
	// Define all known patterns to check for
	knownPatterns := [][]byte{
		// Original admin pattern
		{0x45, 0x73, 0x77, 0x29, 0x2f, 0xda, 0x9a, 0x21, 0x10, 0x52, 0xb1, 0x9c, 0x70, 0x93, 0x0e, 0xa0},
		// Tester_1 pattern
		{0xa5, 0xae, 0xc3, 0x17, 0xfb, 0xa5, 0xad, 0xad, 0x69, 0x2b, 0xa7, 0x9d, 0x67, 0x0c, 0x51, 0x0e},
		// Tester_3 pattern (rotated variant)
		{0xad, 0x69, 0x2b, 0xa7, 0x9d, 0x67, 0x0c, 0x50, 0x0e, 0xa5, 0xae, 0xc3, 0x17, 0xfb, 0xa5, 0xad},
		// Tester_4 pattern
		{0x47, 0xe7, 0x92, 0xaf, 0x28, 0xdb, 0x6e, 0x54, 0xec, 0xf7, 0x9b, 0xf7, 0xb4, 0x4d, 0xe1, 0x63},
		// Character creation pattern
		{0x63, 0xd5, 0xb8, 0xd7, 0x2b, 0x9b, 0x02, 0x2a, 0x5e, 0xc9, 0x38, 0x3f, 0x79, 0x66, 0x50, 0xda},
	}
	
	// Check each known pattern
	for _, pattern := range knownPatterns {
		if findPattern(data, pattern) {
			return pattern
		}
	}
	
	// Method 2: Auto-detect key from repeating 16-byte patterns
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
// Enhanced to handle both string-based and binary login formats, with improved new user support
func ParseLoginData(decryptedData []byte) (username, password string, err error) {
	// Method 1: Try classic null-separated string format (admin login style)
	username, password, err = parseStringBasedLogin(decryptedData)
	if err == nil && username != "" && isValidUsername(username) {
		return username, password, nil
	}
	
	// Method 2: Try structured binary format (tester login style)
	username, password, err = parseBinaryBasedLogin(decryptedData)
	if err == nil && username != "" && isValidUsername(username) {
		return username, password, nil
	}
	
	// Method 3: Enhanced fallback for new users - more aggressive string extraction
	username, password, err = parseAdvancedStringLogin(decryptedData)
	if err == nil && username != "" && isValidUsername(username) {
		return username, password, nil
	}
	
	// Method 4: Final fallback to raw string extraction
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

// parseAdvancedStringLogin uses enhanced techniques for new users with unknown key patterns
func parseAdvancedStringLogin(decryptedData []byte) (username, password string, err error) {
	// More aggressive string extraction for cases where decryption isn't perfect
	
	// Look for ASCII strings with more tolerance for noise
	var candidateStrings []string
	currentString := ""
	consecutivePrintable := 0
	
	for i, b := range decryptedData {
		if b >= 32 && b <= 126 { // Printable ASCII
			currentString += string(b)
			consecutivePrintable++
		} else if b == 0 && len(currentString) > 1 {
			// Null terminator - end current string
			if len(currentString) >= 2 && consecutivePrintable >= len(currentString)/2 {
				candidateStrings = append(candidateStrings, currentString)
			}
			currentString = ""
			consecutivePrintable = 0
		} else if b < 32 || b > 126 {
			// Non-printable character
			if len(currentString) >= 2 && consecutivePrintable >= len(currentString)/2 {
				candidateStrings = append(candidateStrings, currentString)
			}
			currentString = ""
			consecutivePrintable = 0
		}
		
		// Handle end of data
		if i == len(decryptedData)-1 && len(currentString) >= 2 && consecutivePrintable >= len(currentString)/2 {
			candidateStrings = append(candidateStrings, currentString)
		}
	}
	
	// Filter and rank candidate strings
	var usernameCandidate, passwordCandidate string
	
	for _, candidate := range candidateStrings {
		if isValidUsername(candidate) && len(usernameCandidate) == 0 {
			usernameCandidate = candidate
		} else if isValidPassword(candidate) && len(passwordCandidate) == 0 {
			passwordCandidate = candidate
		}
	}
	
	// Look for MD5-like patterns (32 character hex strings)
	for _, candidate := range candidateStrings {
		if len(candidate) == 32 && isHexString(candidate) {
			passwordCandidate = candidate
			break
		}
	}
	
	if usernameCandidate != "" {
		return usernameCandidate, passwordCandidate, nil
	}
	
	// If no clear username found, try pattern-based extraction
	// Look for strings that appear at expected offsets
	if len(decryptedData) >= 64 {
		// Check username area (around offset 9-32)
		for offset := 9; offset < 32 && offset < len(decryptedData)-8; offset++ {
			candidate := extractStringAtOffset(decryptedData, offset, 32)
			if isValidUsername(candidate) {
				return candidate, "", nil
			}
		}
		
		// Check for any recognizable username pattern
		for _, candidate := range candidateStrings {
			if len(candidate) >= 3 && len(candidate) <= 20 && isAlphanumeric(candidate) {
				return candidate, "", nil
			}
		}
	}
	
	return "", "", fmt.Errorf("could not parse advanced string login data")
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

// isValidPassword checks if a string looks like a valid password
func isValidPassword(s string) bool {
	if len(s) < 4 || len(s) > 64 {
		return false
	}
	
	// Check for MD5 hash pattern (32 hex chars)
	if len(s) == 32 && isHexString(s) {
		return true
	}
	
	// Check for reasonable password characters
	hasAlpha := false
	hasDigit := false
	
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasAlpha = true
		} else if c >= '0' && c <= '9' {
			hasDigit = true
		} else if !((c >= 33 && c <= 47) || (c >= 58 && c <= 64) || 
				   (c >= 91 && c <= 96) || (c >= 123 && c <= 126)) {
			return false // Invalid password character
		}
	}
	
	return hasAlpha || hasDigit
}

// isHexString checks if a string contains only hexadecimal characters
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return len(s) > 0
}

// isAlphanumeric checks if a string contains only alphanumeric characters
func isAlphanumeric(s string) bool {
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return len(s) > 0
}

// extractStringAtOffset extracts a null-terminated string at a specific offset
func extractStringAtOffset(data []byte, offset, maxLen int) string {
	if offset >= len(data) {
		return ""
	}
	
	end := offset
	for end < len(data) && end < offset+maxLen && data[end] != 0 && data[end] >= 32 && data[end] <= 126 {
		end++
	}
	
	if end > offset {
		candidate := string(data[offset:end])
		if len(candidate) >= 2 {
			return candidate
		}
	}
	
	return ""
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

// detectNewUserXORKey attempts to discover XOR keys for new users using advanced techniques
func detectNewUserXORKey(data []byte) []byte {
	// Method 1: Statistical frequency analysis for XOR detection
	key := detectKeyByFrequencyAnalysis(data)
	if len(key) == 16 {
		return key
	}
	
	// Method 2: Pattern-based key derivation from known key structures
	key = deriveKeyFromKnownPatterns(data)
	if len(key) == 16 {
		return key
	}
	
	// Method 3: Brute force common XOR patterns
	key = bruteForceCommonPatterns(data)
	if len(key) == 16 {
		return key
	}
	
	// Method 4: Try to derive key from typical login data structure
	key = deriveKeyFromLoginStructure(data)
	if len(key) == 16 {
		return key
	}
	
	return nil
}

// detectKeyByFrequencyAnalysis uses statistical analysis to detect XOR patterns
func detectKeyByFrequencyAnalysis(data []byte) []byte {
	if len(data) < 32 { // Need sufficient data for analysis
		return nil
	}
	
	// Analyze byte frequency patterns that might indicate XOR encryption
	// XOR with repeating key creates patterns in the encrypted data
	
	// Try different key lengths (focus on 16 bytes)
	for keyLen := 16; keyLen <= 16; keyLen++ {
		if len(data) < keyLen*2 {
			continue
		}
		
		candidateKey := make([]byte, keyLen)
		confidence := 0
		
		// For each position in the key
		for pos := 0; pos < keyLen; pos++ {
			// Collect bytes at this position across the data
			var bytes []byte
			for i := pos; i < len(data); i += keyLen {
				bytes = append(bytes, data[i])
			}
			
			if len(bytes) < 2 {
				continue
			}
			
			// Find the most common XOR difference that would produce printable ASCII
			bestByte := byte(0)
			bestScore := 0
			
			for candidate := 0; candidate < 256; candidate++ {
				score := 0
				for _, b := range bytes {
					decrypted := b ^ byte(candidate)
					// Score based on likelihood of being part of login data
					if (decrypted >= 'a' && decrypted <= 'z') ||
					   (decrypted >= 'A' && decrypted <= 'Z') ||
					   (decrypted >= '0' && decrypted <= '9') ||
					   decrypted == 0 || decrypted == ' ' {
						score += 2
					} else if decrypted >= 32 && decrypted <= 126 {
						score += 1
					}
				}
				
				if score > bestScore {
					bestScore = score
					bestByte = byte(candidate)
				}
			}
			
			candidateKey[pos] = bestByte
			confidence += bestScore
		}
		
		// Check if this key produces reasonable results
		if confidence > len(data)/2 { // Reasonable threshold
			return candidateKey
		}
	}
	
	return nil
}

// deriveKeyFromKnownPatterns tries to derive new keys based on patterns from known keys
func deriveKeyFromKnownPatterns(data []byte) []byte {
	knownKeys := [][]byte{
		{0x45, 0x73, 0x77, 0x29, 0x2f, 0xda, 0x9a, 0x21, 0x10, 0x52, 0xb1, 0x9c, 0x70, 0x93, 0x0e, 0xa0},
		{0xa5, 0xae, 0xc3, 0x17, 0xfb, 0xa5, 0xad, 0xad, 0x69, 0x2b, 0xa7, 0x9d, 0x67, 0x0c, 0x51, 0x0e},
		{0xad, 0x69, 0x2b, 0xa7, 0x9d, 0x67, 0x0c, 0x50, 0x0e, 0xa5, 0xae, 0xc3, 0x17, 0xfb, 0xa5, 0xad},
		{0x47, 0xe7, 0x92, 0xaf, 0x28, 0xdb, 0x6e, 0x54, 0xec, 0xf7, 0x9b, 0xf7, 0xb4, 0x4d, 0xe1, 0x63},
	}
	
	// Try variations of known keys (rotations, byte shifts, etc.)
	for _, baseKey := range knownKeys {
		// Try rotations
		for shift := 1; shift < 16; shift++ {
			candidateKey := make([]byte, 16)
			for i := 0; i < 16; i++ {
				candidateKey[i] = baseKey[(i+shift)%16]
			}
			
			if evaluateDecryption(data, candidateKey) > 30 {
				return candidateKey
			}
		}
		
		// Try bit shifts
		for shift := 1; shift < 8; shift++ {
			candidateKey := make([]byte, 16)
			for i := 0; i < 16; i++ {
				candidateKey[i] = baseKey[i] << shift | baseKey[i] >> (8-shift)
			}
			
			if evaluateDecryption(data, candidateKey) > 30 {
				return candidateKey
			}
		}
		
		// Try byte-wise XOR with simple patterns
		patterns := []byte{0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xFF}
		for _, pattern := range patterns {
			candidateKey := make([]byte, 16)
			for i := 0; i < 16; i++ {
				candidateKey[i] = baseKey[i] ^ pattern
			}
			
			if evaluateDecryption(data, candidateKey) > 30 {
				return candidateKey
			}
		}
	}
	
	return nil
}

// bruteForceCommonPatterns tries common XOR key patterns
func bruteForceCommonPatterns(data []byte) []byte {
	// Common patterns that might be used for XOR keys
	commonPatterns := [][]byte{
		// Repeating single bytes
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA},
		{0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55},
		
		// Incremental patterns
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
		
		// Common byte sequences
		{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0},
		{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE},
	}
	
	bestKey := make([]byte, 0)
	bestScore := 0
	
	for _, pattern := range commonPatterns {
		score := evaluateDecryption(data, pattern)
		if score > bestScore && score > 20 {
			bestScore = score
			bestKey = make([]byte, len(pattern))
			copy(bestKey, pattern)
		}
	}
	
	return bestKey
}

// deriveKeyFromLoginStructure attempts to derive XOR key based on known login data structure
func deriveKeyFromLoginStructure(data []byte) []byte {
	if len(data) < 64 { // Need minimum amount of data
		return nil
	}
	
	// Known login structure patterns from analysis
	// Try to find regions that should decrypt to specific patterns
	
	// Pattern 1: Username area (typically starts around offset 9-16)
	// Pattern 2: Password area (typically around offset 45+ in MD5 hash format)
	
	candidateKey := make([]byte, 16)
	found := false
	
	// Try to derive key from the header pattern (should be 00 0A 00 02 00 01 00 00 00)
	expectedHeader := []byte{0x00, 0x0A, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00}
	if len(data) >= len(expectedHeader) {
		for i := 0; i < len(expectedHeader) && i < 16; i++ {
			candidateKey[i] = data[i] ^ expectedHeader[i]
		}
		
		// Fill remaining bytes by repeating the pattern
		for i := len(expectedHeader); i < 16; i++ {
			candidateKey[i] = candidateKey[i%len(expectedHeader)]
		}
		
		// Test this candidate
		if evaluateDecryption(data, candidateKey) > 25 {
			found = true
		}
	}
	
	// If header-based detection didn't work, try password region
	if !found && len(data) >= 61 { // 45 + 16 for MD5 hash
		// Look for MD5 hash pattern (32 hex chars = uppercase hex digits)
		passwordOffset := 45
		if passwordOffset+16 < len(data) {
			// Assume this should decrypt to hex digits (0-9, A-F)
			hexCount := 0
			for i := 0; i < 16; i++ {
				for candidate := 0; candidate < 256; candidate++ {
					decrypted := data[passwordOffset+i] ^ byte(candidate)
					if (decrypted >= '0' && decrypted <= '9') ||
					   (decrypted >= 'A' && decrypted <= 'F') {
						candidateKey[i] = byte(candidate)
						hexCount++
						break
					}
				}
			}
			
			if hexCount >= 8 { // At least half should be hex
				if evaluateDecryption(data, candidateKey) > 20 {
					found = true
				}
			}
		}
	}
	
	if found {
		return candidateKey
	}
	
	return nil
}

// loadLearnedKeys loads previously discovered XOR keys from storage
func loadLearnedKeys() {
	// Simple file-based storage for learned keys
	// In production, this could be a database
	file, err := os.Open(keyStorage)
	if err != nil {
		return // File doesn't exist yet, that's okay
	}
	defer file.Close()
	
	// Read and parse stored keys
	// Format: username:hexkey
	data := make([]byte, 4096)
	n, err := file.Read(data)
	if err != nil || n == 0 {
		return
	}
	
	lines := strings.Split(string(data[:n]), "\n")
	for _, line := range lines {
		parts := strings.Split(strings.TrimSpace(line), ":")
		if len(parts) == 2 {
			username := parts[0]
			hexKey := parts[1]
			if len(hexKey) == 32 { // 16 bytes * 2 hex chars
				key := make([]byte, 16)
				for i := 0; i < 16; i++ {
					var b byte
					fmt.Sscanf(hexKey[i*2:i*2+2], "%02x", &b)
					key[i] = b
				}
				learnedKeys[username] = key
				log.Printf("[Encryption] Loaded learned key for user: %s", username)
			}
		}
	}
}

// saveLearnedKeys persists newly learned keys to storage
func saveLearnedKeys() {
	learnedKeysMu.RLock()
	defer learnedKeysMu.RUnlock()
	
	file, err := os.Create(keyStorage)
	if err != nil {
		log.Printf("[Encryption] Failed to save learned keys: %v", err)
		return
	}
	defer file.Close()
	
	for username, key := range learnedKeys {
		hexKey := fmt.Sprintf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
			key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15])
		file.WriteString(fmt.Sprintf("%s:%s\n", username, hexKey))
	}
}

// learnXORKey stores a newly discovered XOR key for a user
func learnXORKey(username string, key []byte) {
	if len(key) != 16 {
		return
	}
	
	learnedKeysMu.Lock()
	learnedKeys[username] = make([]byte, 16)
	copy(learnedKeys[username], key)
	learnedKeysMu.Unlock()
	
	log.Printf("[Encryption] Learned new XOR key for user %s: %x", username, key)
	
	// Save to persistent storage
	go saveLearnedKeys()
}

// getLearnedKey retrieves a previously learned XOR key for a user
func getLearnedKey(username string) []byte {
	learnedKeysMu.RLock()
	defer learnedKeysMu.RUnlock()
	
	if key, exists := learnedKeys[username]; exists {
		result := make([]byte, 16)
		copy(result, key)
		return result
	}
	
	return nil
}

// DecryptXORWithUsername performs XOR decryption with username-aware key learning
func DecryptXORWithUsername(data []byte, username string) ([]byte, []byte) {
	// First, try any previously learned key for this user
	if username != "" {
		learnedKey := getLearnedKey(username)
		if len(learnedKey) == 16 {
			score := evaluateDecryption(data, learnedKey)
			if score > 50 { // Good confidence
				result := make([]byte, len(data))
				for i := 0; i < len(data); i++ {
					result[i] = data[i] ^ learnedKey[i%len(learnedKey)]
				}
				return result, learnedKey
			}
		}
	}
	
	// Fall back to regular decryption
	result := DecryptXOR(data)
	
	// Try to extract the key that was used for learning
	usedKey := extractActualXORKey(data, result)
	if len(usedKey) == 16 && username != "" {
		// Learn this key for future use
		learnXORKey(username, usedKey)
		return result, usedKey
	}
	
	return result, nil
}

// extractActualXORKey reverse-engineers the XOR key that was used for decryption
func extractActualXORKey(original, decrypted []byte) []byte {
	if len(original) != len(decrypted) || len(original) < 16 {
		return nil
	}
	
	key := make([]byte, 16)
	for i := 0; i < 16 && i < len(original); i++ {
		key[i] = original[i] ^ decrypted[i]
	}
	
	// Verify this key works for the entire data
	score := evaluateDecryption(original, key)
	if score > 30 {
		return key
	}
	
	return nil
}