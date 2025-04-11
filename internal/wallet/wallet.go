package wallet

import (
	"github.com/grendel/godel/pkg/common"
	"github.com/grendel/godel/pkg/matcher"
)

// Using common package types for entries
type UniqueEntry = common.UniqueEntry
type EntryTracker = common.EntryTracker

// IsDuplicate checks if an entry already exists in the tracker
func IsDuplicate(entry UniqueEntry, tracker EntryTracker) bool {
	return common.IsDuplicate(entry, tracker)
}

// DeriveWalletFromKey creates a proper wallet address from a private key or seed phrase
// This follows the correct address structure for each cryptocurrency and attempts
// to derive a cryptographically valid wallet address when possible
func DeriveWalletFromKey(key string, cryptoType matcher.CryptoType, isSeedPhrase bool) string {
	// Convert from matcher.CryptoType to common.CryptoType
	var commonCryptoType common.CryptoType
	
	switch cryptoType {
	case matcher.Bitcoin:
		commonCryptoType = common.Bitcoin
	case matcher.Ethereum:
		commonCryptoType = common.Ethereum
	case matcher.Litecoin:
		commonCryptoType = common.Litecoin
	case matcher.Solana:
		commonCryptoType = common.Solana
	case matcher.Monero:
		commonCryptoType = common.Monero
	case matcher.Cardano:
		commonCryptoType = common.Cardano
	case matcher.Ripple:
		commonCryptoType = common.Ripple
	case matcher.Polkadot:
		commonCryptoType = common.Polkadot
	case matcher.Cosmos:
		commonCryptoType = common.Cosmos
	default:
		commonCryptoType = common.Ethereum // Default to Ethereum
	}
	
	// Use the common implementation
	return common.DeriveWalletAddress(key, commonCryptoType, isSeedPhrase)
}

// IsHex returns true if the string contains only hexadecimal characters
func IsHex(s string) bool {
	return common.IsHex(s)
}