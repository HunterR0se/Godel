package common

import (
	"strings"

	"github.com/grendel/godel/pkg/crypto"
)

// CryptoType represents the type of cryptocurrency
type CryptoType = crypto.CryptoType

// Define crypto types by re-exporting from crypto package for convenience
const (
	Unknown  = crypto.Unknown
	Ethereum = crypto.Ethereum 
	Bitcoin  = crypto.Bitcoin
	Litecoin = crypto.Litecoin
	Solana   = crypto.Solana
	Monero   = crypto.Monero
	Cardano  = crypto.Cardano
	Ripple   = crypto.Ripple
	Polkadot = crypto.Polkadot
	Cosmos   = crypto.Cosmos
)

// UniqueEntry represents a complete wallet entry including file location and credentials
type UniqueEntry struct {
	FileLocation string
	SeedPhrase   string
	PrivateKey   string
	Wallet       string
}

// EntryTracker tracks unique wallet entries to prevent duplicates
type EntryTracker map[string]UniqueEntry

// IsDuplicate checks if an entry already exists in the tracker
func IsDuplicate(entry UniqueEntry, tracker EntryTracker) bool {
	if _, exists := tracker[entry.SeedPhrase]; exists {
		return true
	}
	if _, exists := tracker[entry.PrivateKey]; exists {
		return true
	}
	if _, exists := tracker[entry.Wallet]; exists {
		return true
	}
	return false
}

// AddEntry adds an entry to the tracker
func AddEntry(entry UniqueEntry, tracker EntryTracker) {
	tracker[entry.SeedPhrase] = entry
	tracker[entry.PrivateKey] = entry
	tracker[entry.Wallet] = entry
}

// IsHex returns true if the string contains only hexadecimal characters
func IsHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// DeriveWalletAddress creates a proper wallet address from a private key or seed phrase
// This follows the correct address structure for each cryptocurrency and attempts
// to derive a cryptographically valid wallet address when possible.
// Returns the derived wallet address with appropriate labeling (VERIFIED or DERIVED)
func DeriveWalletAddress(key string, cryptoType CryptoType, isSeedPhrase bool) string {
	// Use the validator registry
	registry := crypto.NewCryptoValidatorRegistry()
	return registry.DeriveWalletAddress(key, cryptoType, isSeedPhrase)
}

// GenerateDeterministicAddress generates deterministic addresses in the proper format
// Deprecated: Use crypto.CryptoValidatorRegistry.deterministicAddress instead
func GenerateDeterministicAddress(keyHasher *crypto.KeyHasher, cryptoType CryptoType) string {
	registry := crypto.NewCryptoValidatorRegistry()
	// Create a key that's unique to the keyHasher
	key := keyHasher.DeriveHexAddress(32)
	// Strip the (DERIVED) label that would be added
	addr := registry.DeriveWalletAddress(key, cryptoType, false)
	if idx := strings.Index(addr, " ("); idx > 0 {
		return addr[:idx]
	}
	return addr
}