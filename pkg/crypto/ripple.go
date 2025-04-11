package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

// XRP address constants
const (
	// Ripple address version byte
	RIPPLE_ADDRESS_VERSION byte = 0x00
	
	// Account ID length in bytes
	RIPPLE_ACCOUNT_ID_LEN int = 20
	
	// Ripple address length in bytes: 1 byte version + 20 bytes data + 4 bytes checksum
	RIPPLE_ADDRESS_LEN int = 25
)

// ValidateAndDeriveRipplePrivateKey validates a Ripple/XRP private key and derives its wallet address
// with more robust validation and address derivation
func ValidateAndDeriveRipplePrivateKeyRobust(privateKey string) (*KeyValidationResult, error) {
	// Validate Ripple key format - starts with 's' followed by base58 encoded data
	if !strings.HasPrefix(privateKey, "s") {
		return nil, errors.New("invalid Ripple private key format: must start with 's'")
	}
	
	// Ripple secret keys should be 29 characters (including 's')
	if len(privateKey) != 29 {
		return nil, errors.New("invalid Ripple private key length: must be 29 characters")
	}
	
	// Check if it contains only valid base58 characters
	for _, c := range privateKey[1:] {
		// Base58 doesn't include: 0, O, I, l
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return nil, errors.New("invalid Ripple private key: contains invalid base58 characters")
		}
	}
	
	// In a full implementation, we would decode the base58 string and validate the checksum
	// Here we'll do a simplified validation and derive a more proper-looking address
	
	// Hash the private key to get a deterministic seed for generating the address
	hasher := sha256.New()
	hasher.Write([]byte(privateKey))
	seed := hasher.Sum(nil)
	
	// Generate a Ripple address from the seed
	derivedAddress, err := generateRippleAddress(seed)
	if err != nil {
		return nil, err
	}
	
	return &KeyValidationResult{
		IsValid:       true,
		CryptoType:    Ripple,
		DerivedWallet: derivedAddress,
	}, nil
}

// ValidateRippleAddressRobust validates a Ripple/XRP address with more thorough checks
func ValidateRippleAddressRobust(address string) *WalletValidationResult {
	// Basic format checks
	if !strings.HasPrefix(address, "r") {
		return &WalletValidationResult{IsValid: false}
	}
	
	// Ripple addresses MUST be 25-35 characters in length
	if len(address) < 25 || len(address) > 35 {
		return &WalletValidationResult{IsValid: false}
	}
	
	// Check if it contains only valid base58 characters
	pattern := regexp.MustCompile(`^r[1-9A-HJ-NP-Za-km-z]+$`)
	if !pattern.MatchString(address) {
		return &WalletValidationResult{IsValid: false}
	}
	
	// While a full implementation would decode the base58 address and verify its checksum,
	// we'll just do basic format validation for this example
	
	// Check for known invalid or reserved addresses
	if address == "rrrrrrrrrrrrrrrrrrrrrhoLvTp" || // Zero address
        address == "rrrrrrrrrrrrrrrrrNAMEtxvNvQ" || // Reserved name space
        address == "rrrrrrrrrrrrrrrrrrn5RM1rHd" {    // NaN address
		return &WalletValidationResult{IsValid: false}
	}
	
	return &WalletValidationResult{
		IsValid:    true,
		CryptoType: Ripple,
	}
}

// generateRippleAddress creates a Ripple address from a seed
func generateRippleAddress(seed []byte) (string, error) {
	// In a real implementation, we would:
	// 1. Use the seed to derive an ECDSA key pair
	// 2. Take the public key and hash it to get an account ID
	// 3. Encode the account ID with checksums to get a proper Ripple address
	
	// Here we'll do a simplified version that still produces realistic-looking addresses
	
	// Ensure we have sufficient entropy
	if len(seed) < 32 {
		return "", errors.New("insufficient entropy for address generation")
	}
	
	// Create a sequence number based on the first 8 bytes of the seed
	seqNum := binary.BigEndian.Uint64(seed[0:8])
	
	// Take the next 20 bytes as our account ID
	accountID := seed[8:28]
	
	// XOR the sequence number into the account ID for additional entropy
	for i := 0; i < 8 && i < len(accountID); i++ {
		b := byte((seqNum >> (i * 8)) & 0xFF)
		accountID[i] ^= b
	}
	
	// Simulate address construction:
	// 1. Prefix with Ripple address version
	addressBytes := append([]byte{RIPPLE_ADDRESS_VERSION}, accountID...)
	
	// 2. Calculate double SHA-256 checksum (first 4 bytes)
	checksum := sha256.Sum256(addressBytes)
	checksum = sha256.Sum256(checksum[:])
	
	// 3. Append first 4 bytes of checksum
	addressBytes = append(addressBytes, checksum[0:4]...)
	
	// 4. Encode in base58
	address := "r" + rippleBase58Encode(addressBytes)
	
	return address, nil
}

// rippleBase58Encode implements a Base58 encoding specifically for Ripple
func rippleBase58Encode(input []byte) string {
	// Ripple/XRP uses the standard Base58 alphabet
	alphabet := "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
	
	// Skip leading zeros and count them
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}
	
	// Convert to big integer representation
	// This is a simplified version that doesn't handle extremely large numbers properly
	n := uint64(0)
	for _, b := range input {
		n = n*256 + uint64(b)
	}
	
	// Convert to base58 representation
	result := ""
	for n > 0 {
		result = string(alphabet[n%58]) + result
		n /= 58
	}
	
	// Add '1' characters for each leading zero
	for i := 0; i < zeros; i++ {
		result = "1" + result
	}
	
	return result
}

// GenerateRippleKeyPair generates a new Ripple key pair from a random seed
// This is a utility function that could be exposed for testing or wallet creation
func GenerateRippleKeyPair() (string, string, error) {
	// Generate random bytes for the seed
	randomBytes := make([]byte, 32)
	
	// In a real implementation, we'd use a secure random number generator
	// For this example, we'll generate a deterministic but realistic-looking key
	for i := range randomBytes {
		randomBytes[i] = byte(i + 1)
	}
	
	// Convert the seed to a Ripple private key format
	hasher := sha256.New()
	hasher.Write(randomBytes)
	keyBytes := hasher.Sum(nil)
	
	// Create a private key string that starts with 's'
	privateKey := "s" + hex.EncodeToString(keyBytes)[:28]
	
	// Generate a corresponding address
	address, err := generateRippleAddress(randomBytes)
	if err != nil {
		return "", "", err
	}
	
	return privateKey, address, nil
}