package protocol

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// LearnedKeys stores dynamically discovered XOR keys for new users
var (
	learnedKeys   = make(map[string][]byte) // username -> XOR key
	learnedKeysMu sync.RWMutex
	keyStorage    = "/tmp/learned_keys.txt" // File to persist learned keys
	
	// Circuit breaker for expensive key detection operations
	keyDetectionAttempts = make(map[string]time.Time) // client IP -> last attempt time
	keyDetectionMutex    sync.RWMutex
	keyDetectionTimeout  = 15 * time.Second // Maximum time for key detection (reduced from 30s)
	
	// Global circuit breaker for system overload protection
	globalKeyDetectionAttempts = 0
	globalKeyDetectionMutex    sync.RWMutex
	globalResetTime           = time.Now()
	maxGlobalAttempts         = 5  // Maximum concurrent attempts across all clients
	globalResetPeriod         = 1 * time.Minute
)

// init loads any previously learned keys asynchronously to prevent startup blocking
func init() {
	// Load keys asynchronously to avoid blocking server startup
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[Encryption] Recovered from panic during async key loading: %v", r)
			}
		}()
		loadLearnedKeys()
	}()
}

// DecryptXORFast performs fast XOR decryption using cached/known patterns only
// Returns nil if no fast path is available (triggers background learning)
func DecryptXORFast(data []byte, clientAddr string) []byte {
	// Check for Bishop protocol format: first 32 bytes = XOR key repeated, then plain text data
	if len(data) > 32 {
		// Check if first 32 bytes contain a repeated 16-byte pattern (XOR key header)
		if len(data) >= 32 && bytes.Equal(data[0:16], data[16:32]) {
			// This is Bishop protocol format - data after byte 32 is plain text
			loginData := data[32:]
			if hasValidLoginPattern(loginData) {
				log.Printf("[Encryption] Bishop protocol format detected for %s - login data is plain text", clientAddr)
				return loginData
			}
		}
	}
	
	// Check learned keys cache first
	learnedKeysMu.RLock()
	for username, cachedKey := range learnedKeys {
		result := make([]byte, len(data))
		for i := 0; i < len(data); i++ {
			result[i] = data[i] ^ cachedKey[i%len(cachedKey)]
		}
		
		// Quick validation - look for readable ASCII patterns
		if hasValidLoginPattern(result) {
			learnedKeysMu.RUnlock()
			log.Printf("[Encryption] Fast decryption successful using cached key for user %s", username)
			return result
		}
	}
	learnedKeysMu.RUnlock()
	
	// Quick pattern extraction (max 500ms for Bishop compatibility)
	fastKey := extractXORKeyDynamicFast(data)
	if fastKey != nil {
		result := make([]byte, len(data))
		for i := 0; i < len(data); i++ {
			result[i] = data[i] ^ fastKey[i%len(fastKey)]
		}
		
		if hasValidLoginPattern(result) {
			log.Printf("[Encryption] Fast pattern extraction successful for %s", clientAddr)
			return result
		}
	}
	
	// Fast path failed
	return nil
}

// extractXORKeyDynamicFast is an optimized version for real-time use
func extractXORKeyDynamicFast(data []byte) []byte {
	if len(data) < 32 {
		return nil
	}
	
	// Fast pattern detection - only check most likely positions
	for i := 0; i <= len(data)-32; i += 16 { // Skip by 16-byte chunks
		if i+32 <= len(data) {
			pattern1 := data[i : i+16]
			pattern2 := data[i+16 : i+32]
			
			// Check if patterns look like potential XOR keys
			if bytesLookEncrypted(pattern1) && bytesLookEncrypted(pattern2) {
				// Quick entropy check
				if hasReasonableEntropy(pattern1) {
					return pattern1
				}
			}
		}
	}
	
	return nil
}

// hasValidLoginPattern checks if decrypted data looks like valid login data
func hasValidLoginPattern(data []byte) bool {
	if len(data) < 16 {
		return false
	}
	
	// Look for common patterns in login data:
	// - ASCII characters
	// - Common username/password patterns
	// - MD5 hash patterns (32 hex chars)
	
	asciiCount := 0
	hexCount := 0
	
	for i, b := range data {
		if i > 64 { // Don't check entire buffer for speed
			break
		}
		
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
			asciiCount++
		}
		
		if (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F') {
			hexCount++
		}
	}
	
	// Reasonable ASCII content or hex patterns (MD5 hash)
	return asciiCount > 8 || hexCount > 20
}

// ParseLoginDataFast is an optimized version of ParseLoginData for fast path
func ParseLoginDataFast(data []byte) (string, string, error) {
	if len(data) < 8 {
		return "", "", fmt.Errorf("data too short for fast parsing")
	}
	
	// Convert to string and look for common patterns quickly
	str := string(data)
	
	// Method 1: Look for null-separated strings (most common)
	parts := strings.Split(str, "\x00")
	if len(parts) >= 2 {
		username := strings.TrimSpace(parts[0])
		password := strings.TrimSpace(parts[1])
		
		if len(username) > 0 && len(password) > 0 && len(username) < 32 && len(password) < 64 {
			// Basic validation - alphanumeric usernames, hex passwords (MD5)
			if isValidUsername(username) && isValidPassword(password) {
				return username, password, nil
			}
		}
	}
	
	// Method 2: Fixed positions (some client versions)
	if len(data) >= 64 {
		// Try extracting from common positions
		username := extractStringFromPosition(data, 0, 16)
		password := extractStringFromPosition(data, 16, 48)
		
		if len(username) > 0 && len(password) > 0 && isValidUsername(username) && isValidPassword(password) {
			return username, password, nil
		}
	}
	
	return "", "", fmt.Errorf("fast parsing failed")
}

// Helper functions for fast validation
func isValidUsername(username string) bool {
	if len(username) < 3 || len(username) > 16 {
		return false
	}
	
	for _, r := range username {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return true
}

func isValidPassword(password string) bool {
	if len(password) < 8 {
		return false
	}
	
	// Check for MD5 hash pattern (32 hex characters)
	if len(password) == 32 {
		for _, r := range password {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
				return false
			}
		}
		return true
	}
	
	// Other password formats
	return len(password) >= 8 && len(password) <= 64
}

func extractStringFromPosition(data []byte, start, maxLen int) string {
	if start >= len(data) {
		return ""
	}
	
	end := start
	for end < len(data) && end < start+maxLen && data[end] != 0 {
		if data[end] < 32 || data[end] > 126 { // Non-printable
			break
		}
		end++
	}
	
	if end > start {
		return string(data[start:end])
	}
	return ""
}

func hasReasonableEntropy(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	
	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}
	
	// Count non-zero frequencies
	nonZero := 0
	for _, f := range freq {
		if f > 0 {
			nonZero++
		}
	}
	
	// Good entropy has many different byte values
	return nonZero >= len(data)/2
}

func bytesLookEncrypted(data []byte) bool {
	// Very basic check - encrypted data usually has reasonable entropy
	if len(data) < 8 {
		return false
	}
	
	var sum int
	for _, b := range data[:8] {
		sum += int(b)
	}
	
	avg := sum / 8
	return avg > 32 && avg < 200 // Reasonable range for encrypted data
}

// DecryptXOR performs XOR decryption on login data
// Enhanced to handle multiple encryption keys found in different user scenarios and new users
func DecryptXOR(data []byte) []byte {
	return DecryptXORWithClientAddr(data, "unknown")
}

// DecryptXORWithClientAddr performs XOR decryption with client address for circuit breaker
// Completely dynamic - no hardcoded keys for any users
func DecryptXORWithClientAddr(data []byte, clientAddr string) []byte {
	// Add overall timeout for the entire decryption process
	done := make(chan []byte, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[Encryption] Recovered from panic in DecryptXORWithClientAddr: %v", r)
				done <- data // Return original data if panic
			}
		}()
		
		log.Printf("[Encryption] Starting dynamic XOR key detection for %s", clientAddr)
		
		// Try to automatically detect the correct XOR key from repeating patterns
		xorKey := extractXORKeyDynamic(data)
		
		if len(xorKey) == 0 {
			// If pattern extraction fails, use advanced detection methods
			// Only if we haven't attempted recently (circuit breaker)
			if canAttemptKeyDetection(clientAddr) {
				log.Printf("[Encryption] Attempting advanced dynamic key detection for %s", clientAddr)
				xorKey = detectNewUserXORKey(data, clientAddr)
				if len(xorKey) == 16 {
					score := evaluateDecryption(data, xorKey)
					log.Printf("[Encryption] Dynamic detection found key: %x (score: %d)", xorKey, score)
				}
			} else {
				log.Printf("[Encryption] Skipping expensive key detection for %s due to circuit breaker", clientAddr)
			}
		}
		
		// If no key found, generate a dynamic key using algorithmic approaches
		if len(xorKey) == 0 {
			log.Printf("[Encryption] No key found, attempting algorithmic key generation for %s", clientAddr)
			xorKey = generateDynamicKey(data)
		}
		
		// Ensure we have a valid key (fallback to null transformation if all else fails)
		if len(xorKey) == 0 {
			log.Printf("[Encryption] All dynamic methods failed, using null transformation for %s", clientAddr)
			xorKey = make([]byte, 16) // All zeros - null transformation
		}
		
		result := make([]byte, len(data))
		for i := 0; i < len(data); i++ {
			result[i] = data[i] ^ xorKey[i%len(xorKey)]
		}
		
		done <- result
	}()
	
	// Wait for completion or timeout
	select {
	case result := <-done:
		return result
	case <-time.After(10 * time.Second):
		log.Printf("[Encryption] DecryptXORWithClientAddr timeout after 10 seconds for %s", clientAddr)
		// Return original data without modification as fallback
		return data
	}
}

// extractXORKeyDynamic tries to extract the XOR key using purely dynamic algorithms
// No hardcoded patterns - completely algorithmic approach
func extractXORKeyDynamic(data []byte) []byte {
	if len(data) < 32 { // Need minimum data for analysis
		return nil
	}
	
	// Method 1: Auto-detect key from repeating 16-byte patterns
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
			log.Printf("[Encryption] Found repeating 16-byte pattern (count: %d)", maxCount)
			return []byte(mostCommonPattern)
		}
	}
	
	// Method 2: Statistical entropy analysis
	// Look for byte sequences with consistent entropy patterns
	if len(data) >= 16 {
		candidateKey := make([]byte, 16)
		confidence := 0
		
		// For each position in potential key
		for pos := 0; pos < 16; pos++ {
			byteFreq := make(map[byte]int)
			
			// Collect bytes at this position across the data
			for i := pos; i < len(data); i += 16 {
				byteFreq[data[i]]++
			}
			
			// Find most frequent byte (likely part of repeating key)
			var mostFreqByte byte
			maxFreq := 0
			for b, freq := range byteFreq {
				if freq > maxFreq {
					maxFreq = freq
					mostFreqByte = b
				}
			}
			
			candidateKey[pos] = mostFreqByte
			confidence += maxFreq
		}
		
		// If we found a pattern with reasonable confidence
		if confidence > len(data)/8 {
			log.Printf("[Encryption] Extracted key via entropy analysis (confidence: %d)", confidence)
			return candidateKey
		}
	}
	
	// Method 3: Look for XOR patterns against known plaintext structures
	// Try to detect keys that would produce common login packet structures
	candidateKey := detectKeyFromStructure(data)
	if len(candidateKey) == 16 {
		log.Printf("[Encryption] Extracted key via structure analysis")
		return candidateKey
	}
	
	return nil
}

// detectKeyFromStructure tries to extract XOR key based on expected packet structure
func detectKeyFromStructure(data []byte) []byte {
	if len(data) < 16 {
		return nil
	}
	
	// Common login packet structures we might expect after decryption:
	// - Packets often start with specific patterns (length fields, type fields)
	// - Null-terminated strings at predictable offsets
	// - Common ASCII characters in username/password fields
	
	candidateKey := make([]byte, 16)
	bestScore := 0
	
	// Try different assumptions about the packet structure
	structureTests := []struct {
		offset     int
		expectedBytes []byte
		weight     int
	}{
		// Common packet header patterns
		{0, []byte{0x00}, 5},  // Often starts with null
		{1, []byte{0x0A}, 3},  // Common length indicator
		{4, []byte{0x00}, 3},  // Padding bytes
		{8, []byte{0x00}, 2},  // More padding
	}
	
	for _, test := range structureTests {
		if test.offset < len(data) && test.offset < 16 {
			for _, expectedByte := range test.expectedBytes {
				key_byte := data[test.offset] ^ expectedByte
				candidateKey[test.offset] = key_byte
				bestScore += test.weight
			}
		}
	}
	
	// Fill remaining key bytes using frequency analysis
	for i := 0; i < 16; i++ {
		if candidateKey[i] == 0 && bestScore < 10 { // Only if we haven't set this byte yet
			// Use most common value at this position
			freq := make(map[byte]int)
			for j := i; j < len(data); j += 16 {
				freq[data[j]]++
			}
			
			var mostCommon byte
			maxCount := 0
			for b, count := range freq {
				if count > maxCount {
					maxCount = count
					mostCommon = b
				}
			}
			candidateKey[i] = mostCommon
		}
	}
	
	// Only return if we have reasonable confidence
	if bestScore > 5 {
		return candidateKey
	}
	
	return nil
}

// generateDynamicKey creates a key using algorithmic approaches when pattern detection fails
func generateDynamicKey(data []byte) []byte {
	if len(data) < 16 {
		return nil
	}
	
	candidateKey := make([]byte, 16)
	
	// Method 1: Use entropy-based analysis
	for i := 0; i < 16; i++ {
		// Collect all bytes at position i (mod 16)
		var positionBytes []byte
		for j := i; j < len(data); j += 16 {
			positionBytes = append(positionBytes, data[j])
		}
		
		if len(positionBytes) > 0 {
			// Calculate the most likely XOR key byte for this position
			// by finding the byte that would maximize ASCII printable characters
			bestByte := byte(0)
			bestScore := 0
			
			for candidate := 0; candidate < 256; candidate++ {
				score := 0
				for _, b := range positionBytes {
					decrypted := b ^ byte(candidate)
					if (decrypted >= 32 && decrypted <= 126) || decrypted == 0 {
						score++
					}
				}
				
				if score > bestScore {
					bestScore = score
					bestByte = byte(candidate)
				}
			}
			
			candidateKey[i] = bestByte
		}
	}
	
	// Method 2: If entropy approach doesn't work, use differential analysis
	score := evaluateDecryption(data, candidateKey)
	if score < 10 {
		// Try differential cryptanalysis approach
		for i := 0; i < 16; i++ {
			// Look for patterns in the differences between bytes
			if i < len(data)-1 {
				// Simple differential - adjust key to maximize structure
				diff := data[i] ^ data[i+1]
				candidateKey[i] = diff
			}
		}
	}
	
	// Final validation
	finalScore := evaluateDecryption(data, candidateKey)
	if finalScore > 5 { // Very low threshold since this is last resort
		log.Printf("[Encryption] Generated dynamic key with score: %d", finalScore)
		return candidateKey
	}
	
	return nil
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
// Uses dynamic key selection - no hardcoded keys
func EncryptXOR(data []byte) []byte {
	return EncryptXORWithKey(data, nil)
}

// EncryptXORWithKey performs XOR encryption with a specific key
// If key is nil, attempts to use a learned key or generates one dynamically
func EncryptXORWithKey(data []byte, key []byte) []byte {
	var xorKey []byte
	
	if key != nil && len(key) == 16 {
		xorKey = key
	} else {
		// Try to get a previously learned key (from the most recent successful decryption)
		// In a more sophisticated implementation, this could be context-aware
		xorKey = getLastUsedKey()
		
		if len(xorKey) == 0 {
			// Generate a dynamic key for encryption
			// For responses, we can use a simple algorithmic key
			xorKey = generateResponseKey(data)
		}
	}
	
	// Ensure we have a valid key
	if len(xorKey) == 0 {
		// Last resort: use a computed key based on data characteristics
		xorKey = make([]byte, 16)
		for i := 0; i < 16; i++ {
			// Use a simple hash of the data position
			xorKey[i] = byte((i + len(data)) % 256)
		}
		log.Printf("[Encryption] Using computed fallback key for encryption")
	}
	
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ xorKey[i%len(xorKey)]
	}
	
	return result
}

// ParseLoginData parses decrypted login data to extract username and password
// Enhanced to handle both string-based and binary login formats, with improved new user support and timeout protection
func ParseLoginData(decryptedData []byte) (username, password string, err error) {
	// Add timeout protection for parsing operations
	done := make(chan struct {
		username string
		password string
		err      error
	}, 1)
	
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[Encryption] Recovered from panic in ParseLoginData: %v", r)
				done <- struct {
					username string
					password string
					err      error
				}{"", "", fmt.Errorf("parsing panic: %v", r)}
			}
		}()
		
		// Limit data size to prevent memory issues
		if len(decryptedData) > 1024 {
			decryptedData = decryptedData[:1024]
		}
		
		// Method 1: Try classic null-separated string format (admin login style)
		username, password, err := parseStringBasedLogin(decryptedData)
		if err == nil && username != "" && isValidUsername(username) {
			done <- struct {
				username string
				password string
				err      error
			}{username, password, nil}
			return
		}
		
		// Method 2: Try structured binary format (tester login style)
		username, password, err = parseBinaryBasedLogin(decryptedData)
		if err == nil && username != "" && isValidUsername(username) {
			done <- struct {
				username string
				password string
				err      error
			}{username, password, nil}
			return
		}
		
		// Method 3: Enhanced fallback for new users - more aggressive string extraction
		username, password, err = parseAdvancedStringLogin(decryptedData)
		if err == nil && username != "" && isValidUsername(username) {
			done <- struct {
				username string
				password string
				err      error
			}{username, password, nil}
			return
		}
		
		// Method 4: Final fallback to raw string extraction
		username, password, err = parseRawStringLogin(decryptedData)
		done <- struct {
			username string
			password string
			err      error
		}{username, password, err}
	}()
	
	// Wait for completion or timeout
	select {
	case result := <-done:
		return result.username, result.password, result.err
	case <-time.After(5 * time.Second):
		log.Printf("[Encryption] ParseLoginData timeout after 5 seconds")
		return "", "", fmt.Errorf("parsing timeout after 5 seconds")
	}
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
	// Limit processing to prevent infinite loops
	if len(decryptedData) > 512 {
		decryptedData = decryptedData[:512]
	}
	
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
		maxOffset := len(decryptedData) - 32
		if maxOffset > 100 { // Limit search range
			maxOffset = 100
		}
		
		for offset := 0; offset < maxOffset; offset += 4 {
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
				
				if nullPos > 2 && nullPos < 30 { // Found a reasonable null-terminated string
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
	// Limit processing to prevent infinite loops
	if len(decryptedData) > 512 {
		decryptedData = decryptedData[:512]
	}
	
	// Look for ASCII strings with more tolerance for noise
	var candidateStrings []string
	currentString := ""
	consecutivePrintable := 0
	maxStrings := 10 // Limit number of candidate strings
	
	for i, b := range decryptedData {
		if len(candidateStrings) >= maxStrings {
			break // Prevent too many candidates
		}
		
		if b >= 32 && b <= 126 { // Printable ASCII
			currentString += string(b)
			consecutivePrintable++
			
			// Prevent extremely long strings
			if len(currentString) > 64 {
				currentString = currentString[:64]
				break
			}
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
		if len(candidate) > 64 { // Additional safety check
			continue
		}
		
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
		// Check username area (around offset 9-32) - limit search range
		maxOffset := 32
		if maxOffset > len(decryptedData)-8 {
			maxOffset = len(decryptedData) - 8
		}
		
		for offset := 9; offset < maxOffset; offset++ {
			candidate := extractStringAtOffset(decryptedData, offset, 32)
			if isValidUsername(candidate) {
				return candidate, "", nil
			}
		}
		
		// Check for any recognizable username pattern - limited
		processed := 0
		for _, candidate := range candidateStrings {
			if processed >= 5 { // Limit processing
				break
			}
			if len(candidate) >= 3 && len(candidate) <= 20 && isAlphanumeric(candidate) {
				return candidate, "", nil
			}
			processed++
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

// Last used key storage for encryption consistency
var (
	lastUsedKey     []byte
	lastUsedKeyMu   sync.RWMutex
)

// setLastUsedKey stores the key that was successfully used for decryption
func setLastUsedKey(key []byte) {
	if len(key) == 16 {
		lastUsedKeyMu.Lock()
		lastUsedKey = make([]byte, 16)
		copy(lastUsedKey, key)
		lastUsedKeyMu.Unlock()
	}
}

// getLastUsedKey retrieves the most recently used key for encryption
func getLastUsedKey() []byte {
	lastUsedKeyMu.RLock()
	defer lastUsedKeyMu.RUnlock()
	
	if len(lastUsedKey) == 16 {
		result := make([]byte, 16)
		copy(result, lastUsedKey)
		return result
	}
	
	return nil
}

// generateResponseKey creates a dynamic key for response encryption
func generateResponseKey(data []byte) []byte {
	key := make([]byte, 16)
	
	// Method 1: Use data characteristics to generate key
	if len(data) > 0 {
		// Create key based on data content and length
		seed := uint32(len(data))
		for i := 0; i < 16; i++ {
			// Simple linear congruential generator for key generation
			seed = (seed*1103515245 + 12345) % (1 << 31)
			key[i] = byte(seed % 256)
		}
	} else {
		// Method 2: Time-based key generation as fallback
		now := time.Now().UnixNano()
		for i := 0; i < 16; i++ {
			key[i] = byte((now >> (i * 4)) % 256)
		}
	}
	
	log.Printf("[Encryption] Generated response key: %x", key)
	return key
}
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

// canAttemptKeyDetection implements aggressive circuit breaker pattern for expensive key detection
func canAttemptKeyDetection(clientAddr string) bool {
	// Global circuit breaker check first
	globalKeyDetectionMutex.Lock()
	
	// Reset global counter if enough time has passed
	if time.Since(globalResetTime) > globalResetPeriod {
		globalKeyDetectionAttempts = 0
		globalResetTime = time.Now()
	}
	
	// Check if we've exceeded global limit
	if globalKeyDetectionAttempts >= maxGlobalAttempts {
		globalKeyDetectionMutex.Unlock()
		log.Printf("[Encryption] Global circuit breaker active - too many attempts (%d/%d)", globalKeyDetectionAttempts, maxGlobalAttempts)
		return false
	}
	
	globalKeyDetectionMutex.Unlock()
	
	// Per-client circuit breaker
	keyDetectionMutex.Lock()
	defer keyDetectionMutex.Unlock()
	
	lastAttempt, exists := keyDetectionAttempts[clientAddr]
	if !exists {
		keyDetectionAttempts[clientAddr] = time.Now()
		
		// Increment global counter
		globalKeyDetectionMutex.Lock()
		globalKeyDetectionAttempts++
		globalKeyDetectionMutex.Unlock()
		
		return true
	}
	
	// More aggressive cooldown - reduced from 5 minutes to 2 minutes
	if time.Since(lastAttempt) > 2*time.Minute {
		keyDetectionAttempts[clientAddr] = time.Now()
		
		// Increment global counter
		globalKeyDetectionMutex.Lock()
		globalKeyDetectionAttempts++
		globalKeyDetectionMutex.Unlock()
		
		return true
	}
	
	return false
}

// detectNewUserXORKey attempts to discover XOR keys for new users using advanced techniques
// Now includes timeout and progress logging to prevent hanging
func detectNewUserXORKey(data []byte, clientAddr string) []byte {
	log.Printf("[Encryption] Starting new user XOR key detection for %s", clientAddr)
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), keyDetectionTimeout)
	defer cancel()
	
	// Method 1: Statistical frequency analysis for XOR detection
	log.Printf("[Encryption] Trying frequency analysis...")
	key := detectKeyByFrequencyAnalysisWithTimeout(ctx, data)
	if len(key) == 16 {
		log.Printf("[Encryption] Found key via frequency analysis: %x", key)
		return key
	}
	
	// Check if we should continue (timeout check)
	select {
	case <-ctx.Done():
		log.Printf("[Encryption] Key detection timeout for %s", clientAddr)
		return nil
	default:
	}
	
	// Method 2: Pattern-based key derivation from known key structures  
	log.Printf("[Encryption] Trying pattern-based derivation...")
	key = deriveKeyFromKnownPatternsWithTimeout(ctx, data)
	if len(key) == 16 {
		log.Printf("[Encryption] Found key via pattern derivation: %x", key)
		return key
	}
	
	// Check timeout again
	select {
	case <-ctx.Done():
		log.Printf("[Encryption] Key detection timeout for %s", clientAddr)
		return nil
	default:
	}
	
	// Method 3: Brute force common XOR patterns (fast)
	log.Printf("[Encryption] Trying brute force patterns...")
	key = bruteForceCommonPatterns(data)
	if len(key) == 16 {
		log.Printf("[Encryption] Found key via brute force: %x", key)
		return key
	}
	
	// Method 4: Try to derive key from typical login data structure
	log.Printf("[Encryption] Trying login structure analysis...")
	key = deriveKeyFromLoginStructure(data)
	if len(key) == 16 {
		log.Printf("[Encryption] Found key via login structure: %x", key)
		return key
	}
	
	log.Printf("[Encryption] No suitable XOR key found for %s", clientAddr)
	return nil
}

// detectKeyByFrequencyAnalysisWithTimeout uses statistical analysis to detect XOR patterns with timeout
func detectKeyByFrequencyAnalysisWithTimeout(ctx context.Context, data []byte) []byte {
	if len(data) < 32 { // Need sufficient data for analysis
		return nil
	}
	
	// Optimized: Only try 16-byte keys as that's what we know JX2 uses
	keyLen := 16
	if len(data) < keyLen*2 {
		return nil
	}
	
	candidateKey := make([]byte, keyLen)
	confidence := 0
	
	// For each position in the key
	for pos := 0; pos < keyLen; pos++ {
		// Check for timeout
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		
		// Collect bytes at this position across the data (optimized: limit samples)
		var bytes []byte
		maxSamples := 20 // Limit samples to speed up analysis
		sampleCount := 0
		for i := pos; i < len(data) && sampleCount < maxSamples; i += keyLen {
			bytes = append(bytes, data[i])
			sampleCount++
		}
		
		if len(bytes) < 2 {
			continue
		}
		
		// Find the most common XOR difference that would produce printable ASCII
		bestByte := byte(0)
		bestScore := 0
		
		// Optimized: Test fewer candidates, focus on likely ranges
		candidates := []int{}
		// Common ASCII ranges that might be XORed
		for c := 32; c <= 126; c++ { // Printable ASCII
			candidates = append(candidates, c)
		}
		for c := 0; c <= 31; c++ { // Control chars
			candidates = append(candidates, c)
		}
		
		for _, candidate := range candidates {
			score := 0
			for _, b := range bytes {
				decrypted := b ^ byte(candidate)
				// Score based on likelihood of being part of login data
				if (decrypted >= 'a' && decrypted <= 'z') ||
				   (decrypted >= 'A' && decrypted <= 'Z') ||
				   (decrypted >= '0' && decrypted <= '9') {
					score += 3 // Higher score for alphanumeric
				} else if decrypted == 0 || decrypted == ' ' {
					score += 2 // Good score for null/space
				} else if decrypted >= 32 && decrypted <= 126 {
					score += 1 // Lower score for other printable
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
	
	// Check if this key produces reasonable results (lowered threshold)
	if confidence > len(data)/4 { // More lenient threshold
		return candidateKey
	}
	
	return nil
}

// detectKeyByFrequencyAnalysis uses statistical analysis to detect XOR patterns (deprecated - use timeout version)
func detectKeyByFrequencyAnalysis(data []byte) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return detectKeyByFrequencyAnalysisWithTimeout(ctx, data)
}

// deriveKeyFromKnownPatternsWithTimeout tries to derive new keys based on dynamic analysis with timeout
// No hardcoded keys - uses algorithmic pattern generation
func deriveKeyFromKnownPatternsWithTimeout(ctx context.Context, data []byte) []byte {
	if len(data) < 16 {
		return nil
	}
	
	log.Printf("[Encryption] Starting pattern-based key derivation (dynamic)")
	
	// Method 1: Generate candidate keys using rotational patterns
	baseKey := make([]byte, 16)
	
	// Create a base pattern from the data itself
	for i := 0; i < 16; i++ {
		if i < len(data) {
			baseKey[i] = data[i % len(data)]
		} else {
			baseKey[i] = byte(i) // Fallback pattern
		}
	}
	
	// Try rotations of the base pattern
	for shift := 1; shift < 16; shift += 2 { // Test every other rotation
		// Check for timeout
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		
		candidateKey := make([]byte, 16)
		for i := 0; i < 16; i++ {
			candidateKey[i] = baseKey[(i+shift)%16]
		}
		
		if evaluateDecryption(data, candidateKey) > 30 {
			log.Printf("[Encryption] Found key via rotation (shift: %d)", shift)
			return candidateKey
		}
	}
	
	// Method 2: Bit manipulation patterns
	for shift := 1; shift < 8; shift += 2 { // Test every other shift
		// Check for timeout
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		
		candidateKey := make([]byte, 16)
		for i := 0; i < 16; i++ {
			candidateKey[i] = baseKey[i] << shift | baseKey[i] >> (8-shift)
		}
		
		if evaluateDecryption(data, candidateKey) > 30 {
			log.Printf("[Encryption] Found key via bit shift (shift: %d)", shift)
			return candidateKey
		}
	}
	
	// Method 3: XOR with algorithmic patterns
	patterns := []byte{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xFF, 0xAA, 0x55}
	for _, pattern := range patterns {
		// Check for timeout
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		
		candidateKey := make([]byte, 16)
		for i := 0; i < 16; i++ {
			candidateKey[i] = baseKey[i] ^ pattern
		}
		
		if evaluateDecryption(data, candidateKey) > 30 {
			log.Printf("[Encryption] Found key via XOR pattern (0x%02X)", pattern)
			return candidateKey
		}
	}
	
	// Method 4: Frequency-based pattern derivation
	candidateKey := deriveFromFrequencyAnalysis(data)
	if len(candidateKey) == 16 {
		score := evaluateDecryption(data, candidateKey)
		if score > 25 {
			log.Printf("[Encryption] Found key via frequency derivation (score: %d)", score)
			return candidateKey
		}
	}
	
	return nil
}

// deriveFromFrequencyAnalysis creates a key based on byte frequency patterns
func deriveFromFrequencyAnalysis(data []byte) []byte {
	if len(data) < 16 {
		return nil
	}
	
	candidateKey := make([]byte, 16)
	
	// For each key position, find the byte value that maximizes expected plaintext
	for pos := 0; pos < 16; pos++ {
		byteScores := make(map[byte]int)
		
		// Analyze all bytes at this position
		for i := pos; i < len(data); i += 16 {
			currentByte := data[i]
			
			// Try each possible key byte
			for keyByte := 0; keyByte < 256; keyByte++ {
				decrypted := currentByte ^ byte(keyByte)
				
				// Score based on likelihood of being meaningful plaintext
				score := 0
				if decrypted >= 'a' && decrypted <= 'z' {
					score = 5 // Lowercase letters
				} else if decrypted >= 'A' && decrypted <= 'Z' {
					score = 4 // Uppercase letters
				} else if decrypted >= '0' && decrypted <= '9' {
					score = 3 // Numbers
				} else if decrypted == 0 || decrypted == ' ' {
					score = 2 // Null/space
				} else if decrypted >= 32 && decrypted <= 126 {
					score = 1 // Other printable
				}
				
				byteScores[byte(keyByte)] += score
			}
		}
		
		// Find the key byte with the highest score
		bestByte := byte(0)
		bestScore := 0
		for keyByte, score := range byteScores {
			if score > bestScore {
				bestScore = score
				bestByte = keyByte
			}
		}
		
		candidateKey[pos] = bestByte
	}
	
	return candidateKey
}

// deriveKeyFromKnownPatterns tries to derive new keys based on patterns from known keys (deprecated)
func deriveKeyFromKnownPatterns(data []byte) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return deriveKeyFromKnownPatternsWithTimeout(ctx, data)
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

// loadLearnedKeys loads previously discovered XOR keys from storage with timeout protection
func loadLearnedKeys() {
	// Wrap file operations in a timeout to prevent hanging
	done := make(chan bool, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[Encryption] Recovered from panic in loadLearnedKeys: %v", r)
			}
			done <- true
		}()
		
		// Simple file-based storage for learned keys
		// In production, this could be a database
		file, err := os.Open(keyStorage)
		if err != nil {
			return // File doesn't exist yet, that's okay
		}
		defer file.Close()
		
		// Read and parse stored keys with size limits
		// Format: username:hexkey
		data := make([]byte, 4096) // Limit file size to prevent memory issues
		n, err := file.Read(data)
		if err != nil || n == 0 {
			return
		}
		
		// Limit number of lines processed to prevent infinite loops
		content := string(data[:n])
		if len(content) > 4000 { // Additional safety check
			content = content[:4000]
		}
		
		lines := strings.Split(content, "\n")
		processed := 0
		maxLines := 50 // Limit number of lines to process
		
		for _, line := range lines {
			if processed >= maxLines {
				break
			}
			
			line = strings.TrimSpace(line)
			if len(line) == 0 || len(line) > 100 { // Skip empty or overly long lines
				continue
			}
			
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				username := strings.TrimSpace(parts[0])
				hexKey := strings.TrimSpace(parts[1])
				
				// Validate inputs to prevent issues
				if len(username) > 0 && len(username) <= 32 && len(hexKey) == 32 {
					key := make([]byte, 16)
					validHex := true
					
					for i := 0; i < 16; i++ {
						if i*2+1 >= len(hexKey) {
							validHex = false
							break
						}
						var b byte
						_, err := fmt.Sscanf(hexKey[i*2:i*2+2], "%02x", &b)
						if err != nil {
							validHex = false
							break
						}
						key[i] = b
					}
					
					if validHex {
						learnedKeys[username] = key
						log.Printf("[Encryption] Loaded learned key for user: %s", username)
					}
				}
			}
			processed++
		}
	}()
	
	// Wait for completion or timeout
	select {
	case <-done:
		// Completed successfully
	case <-time.After(5 * time.Second):
		log.Printf("[Encryption] loadLearnedKeys timeout after 5 seconds")
		// Don't block startup for this
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
// Completely dynamic approach with key storage for encryption consistency
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
				
				// Store this key as the last used key for encryption consistency
				setLastUsedKey(learnedKey)
				return result, learnedKey
			}
		}
	}
	
	// Fall back to dynamic decryption
	result := DecryptXOR(data)
	
	// Try to extract the key that was used for learning
	usedKey := extractActualXORKey(data, result)
	if len(usedKey) == 16 {
		// Store this key as the last used key for encryption consistency
		setLastUsedKey(usedKey)
		
		if username != "" {
			// Learn this key for future use
			learnXORKey(username, usedKey)
		}
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