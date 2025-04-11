package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// KeyHasher is a utility for deriving deterministic addresses from keys
type KeyHasher struct {
	keyHash []byte
}

// NewKeyHasher creates a new KeyHasher for the given key
func NewKeyHasher(key string) *KeyHasher {
	// Normalize the key
	key = strings.TrimSpace(key)
	if strings.HasPrefix(key, "0x") {
		key = key[2:]
	}

	// Create a SHA256 hash of the key
	hasher := sha256.New()
	hasher.Write([]byte(key))
	keyHash := hasher.Sum(nil)

	return &KeyHasher{
		keyHash: keyHash,
	}
}

// DeriveHexAddress creates a hex-encoded address of the specified length
func (kh *KeyHasher) DeriveHexAddress(length int) string {
	if length > len(kh.keyHash) {
		// If we need more bytes, create another hash of our hash
		hasher := sha256.New()
		hasher.Write(kh.keyHash)
		extendedHash := hasher.Sum(nil)
		return hex.EncodeToString(extendedHash[:length])
	}
	
	// Otherwise just use the first n bytes
	return hex.EncodeToString(kh.keyHash[:length])
}

// DeriveBase58Address creates a base58-encoded address of the specified length
func (kh *KeyHasher) DeriveBase58Address(length int) string {
	// Simplified base58 charset
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	
	// Get bytes to encode
	var bytesToEncode []byte
	if length > len(kh.keyHash) {
		// If we need more bytes, create another hash of our hash
		hasher := sha256.New()
		hasher.Write(kh.keyHash)
		bytesToEncode = hasher.Sum(nil)
	} else {
		bytesToEncode = kh.keyHash[:length]
	}
	
	// Convert to base58-ish (simplified algorithm)
	result := ""
	for _, b := range bytesToEncode {
		result += string(alphabet[b%58])
	}
	
	// Pad if needed
	for len(result) < length {
		result += string(alphabet[bytesToEncode[0]%58])
	}
	
	return result[:length]
}

// DeriveBech32Address creates a bech32-like address of the specified length
func (kh *KeyHasher) DeriveBech32Address(length int) string {
	// Bech32 only uses these characters
	const alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	
	// Get bytes to encode
	var bytesToEncode []byte
	if length > len(kh.keyHash) {
		// If we need more bytes, create another hash of our hash
		hasher := sha256.New()
		hasher.Write(kh.keyHash)
		bytesToEncode = hasher.Sum(nil)
	} else {
		bytesToEncode = kh.keyHash[:length]
	}
	
	// Convert to bech32-ish format (simplified algorithm)
	result := ""
	for _, b := range bytesToEncode {
		result += string(alphabet[b%32])
	}
	
	// Pad if needed
	for len(result) < length {
		result += string(alphabet[bytesToEncode[0]%32])
	}
	
	return result[:length]
}

// DeriveBytes returns raw bytes of a specific length derived from the key hash
// This is useful for more complex derivations like Polkadot addresses
func (kh *KeyHasher) DeriveBytes(length int) []byte {
	if length > len(kh.keyHash) {
		// If we need more bytes, create another hash of our hash
		hasher := sha256.New()
		hasher.Write(kh.keyHash)
		extendedHash := hasher.Sum(nil)
		return extendedHash[:length]
	}
	
	// Otherwise just use the first n bytes
	return kh.keyHash[:length]
}

// DeriveBitcoinWIF creates a Bitcoin/Litecoin WIF-like string of the specified length
func (kh *KeyHasher) DeriveBitcoinWIF(length int) string {
	// WIF uses Base58 but with a specific pattern
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	
	// Get bytes to encode - use a double-hash for more entropy
	hasher := sha256.New()
	hasher.Write(kh.keyHash)
	bytesToEncode := hasher.Sum(nil)
	
	// Convert to base58-like format with restrictions for WIF
	result := ""
	for _, b := range bytesToEncode {
		// WIF typically has more uppercase than lowercase
		if b%3 == 0 {
			// Use uppercase 30% of the time
			result += string(alphabet[b%26+9])  // Range from 'A' to 'Z' part of the alphabet
		} else {
			// Use digits or lowercase the rest
			result += string(alphabet[b%58])
		}
	}
	
	// Pad if needed
	for len(result) < length {
		result += string(alphabet[bytesToEncode[0]%58])
	}
	
	return result[:length]
}