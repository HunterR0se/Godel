package matcher

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// UniqueCryptoEntry represents a unique cryptographic entry (seed phrase + private key + wallet address)
type UniqueCryptoEntry struct {
	FileLocation  string
	LineNumber    int
	SeedPhrase    string
	PrivateKey    string
	WalletAddress string
	CryptoType    CryptoType
	Type          MatchType
	Probability   float64
}

// DeduplicateResults takes a slice of MatchResults and returns a new slice with duplicates removed
// using multiple factors for identifying duplicates:
// - Identical seed phrases (normalized)
// - Matching private keys (normalized)
// - Identical wallet addresses
// - Same file location and nearby line numbers
func DeduplicateResults(results []MatchResult) []MatchResult {
	// Create map of unique entries by their normalized identifiers
	uniqueEntries := make(map[string]*UniqueCryptoEntry)
	
	// Track seen identifiers
	seenSeedPhrases := make(map[string]bool)
	seenPrivateKeys := make(map[string]bool)
	seenWalletAddresses := make(map[string]bool)
	
	// First pass: extract unique identifiers from all results
	for _, result := range results {
		// Create a unique entry based on the result type
		entry := &UniqueCryptoEntry{
			// FileLocation: result.FileLocation, // MatchResult doesn't have FileLocation field
			LineNumber:   result.LineNumber,
			CryptoType:   result.CryptoType,
			Type:         result.Type,
			Probability:  result.Probability,
		}
		
		// Process based on result type
		switch result.Type {
		case SeedPhrase:
			// Store the seed phrase
			entry.SeedPhrase = normalizeSeedPhrase(result.Content)
			
			// Extract derived keys and wallet addresses if available
			for _, key := range result.AssociatedKeys {
				if strings.HasPrefix(key, "Private Key:") {
					entry.PrivateKey = normalizePrivateKey(strings.TrimPrefix(key, "Private Key: "))
				} else if strings.HasPrefix(key, "Wallet:") || strings.HasPrefix(key, "Address:") {
					entry.WalletAddress = normalizeWalletAddress(strings.TrimPrefix(
						strings.TrimPrefix(key, "Wallet: "),
						"Address: "))
				}
			}
			
			// Use seed phrase as the identifier
			identifier := "seed:" + entry.SeedPhrase
			if !seenSeedPhrases[entry.SeedPhrase] {
				uniqueEntries[identifier] = entry
				seenSeedPhrases[entry.SeedPhrase] = true
			}
			
		case PrivateKey:
			// Store the private key
			entry.PrivateKey = normalizePrivateKey(result.Content)
			
			// Extract wallet address if available
			for _, key := range result.AssociatedKeys {
				if strings.HasPrefix(key, "Wallet:") || strings.HasPrefix(key, "Address:") {
					entry.WalletAddress = normalizeWalletAddress(strings.TrimPrefix(
						strings.TrimPrefix(key, "Wallet: "),
						"Address: "))
				}
			}
			
			// Use private key as the identifier
			identifier := "key:" + entry.PrivateKey
			if !seenPrivateKeys[entry.PrivateKey] {
				uniqueEntries[identifier] = entry
				seenPrivateKeys[entry.PrivateKey] = true
			}
			
		case WalletAddress:
			// Store the wallet address
			entry.WalletAddress = normalizeWalletAddress(result.Content)
			
			// Use wallet address as the identifier
			identifier := "addr:" + entry.WalletAddress
			if !seenWalletAddresses[entry.WalletAddress] {
				uniqueEntries[identifier] = entry
				seenWalletAddresses[entry.WalletAddress] = true
			}
			
		default:
			// For context matches, process the associated keys
			// Extract any seed phrases, private keys, or wallet addresses
			hasSeedPhrase := false
			hasPrivateKey := false
			hasWalletAddress := false
			
			for _, key := range result.AssociatedKeys {
				if strings.HasPrefix(key, "Seed Phrase:") {
					seedPhrase := normalizeSeedPhrase(strings.TrimPrefix(key, "Seed Phrase: "))
					entry.SeedPhrase = seedPhrase
					hasSeedPhrase = true
				} else if strings.HasPrefix(key, "Private Key:") {
					privateKey := normalizePrivateKey(strings.TrimPrefix(key, "Private Key: "))
					entry.PrivateKey = privateKey
					hasPrivateKey = true
				} else if strings.HasPrefix(key, "Wallet:") || strings.HasPrefix(key, "Address:") {
					walletAddress := normalizeWalletAddress(strings.TrimPrefix(
						strings.TrimPrefix(key, "Wallet: "),
						"Address: "))
					entry.WalletAddress = walletAddress
					hasWalletAddress = true
				}
			}
			
			// Only add if we have some unique crypto information
			if hasSeedPhrase && !seenSeedPhrases[entry.SeedPhrase] {
				identifier := "seed:" + entry.SeedPhrase
				uniqueEntries[identifier] = entry
				seenSeedPhrases[entry.SeedPhrase] = true
			} else if hasPrivateKey && !seenPrivateKeys[entry.PrivateKey] {
				identifier := "key:" + entry.PrivateKey
				uniqueEntries[identifier] = entry
				seenPrivateKeys[entry.PrivateKey] = true
			} else if hasWalletAddress && !seenWalletAddresses[entry.WalletAddress] {
				identifier := "addr:" + entry.WalletAddress
				uniqueEntries[identifier] = entry
				seenWalletAddresses[entry.WalletAddress] = true
			} else if hasSeedPhrase || hasPrivateKey || hasWalletAddress {
				// If we have crypto data but it's a duplicate, skip this entry
				continue
			} else {
				// If no crypto data, create a hash of the content as identifier
				identifier := "context:" + createContentFingerprint(result.Content, result.AssociatedKeys)
				uniqueEntries[identifier] = entry
			}
		}
	}
	
	// Second pass: rebuild deduplicated result list from unique entries
	var deduplicated []MatchResult
	
	// Create mapping from unique entries back to original results
	// to preserve as much of the original result structure as possible
	for _, result := range results {
		// Try to find a matching unique entry
		var identifier string
		
		switch result.Type {
		case SeedPhrase:
			seedPhrase := normalizeSeedPhrase(result.Content)
			identifier = "seed:" + seedPhrase
			
			// Skip if we've already processed this seed phrase
			if _, exists := uniqueEntries[identifier]; !exists {
				continue
			}
			
			// Remove this entry from uniqueEntries to avoid duplicates
			delete(uniqueEntries, identifier)
			
		case PrivateKey:
			privateKey := normalizePrivateKey(result.Content)
			identifier = "key:" + privateKey
			
			// Skip if we've already processed this private key
			if _, exists := uniqueEntries[identifier]; !exists {
				continue
			}
			
			// Remove this entry from uniqueEntries to avoid duplicates
			delete(uniqueEntries, identifier)
			
		case WalletAddress:
			walletAddress := normalizeWalletAddress(result.Content)
			identifier = "addr:" + walletAddress
			
			// Skip if we've already processed this wallet address
			if _, exists := uniqueEntries[identifier]; !exists {
				continue
			}
			
			// Remove this entry from uniqueEntries to avoid duplicates
			delete(uniqueEntries, identifier)
			
		default:
			// For context matches, check if any of the associated keys match a unique entry
			shouldAdd := false
			
			for _, key := range result.AssociatedKeys {
				if strings.HasPrefix(key, "Seed Phrase:") {
					seedPhrase := normalizeSeedPhrase(strings.TrimPrefix(key, "Seed Phrase: "))
					identifier = "seed:" + seedPhrase
					if _, exists := uniqueEntries[identifier]; exists {
						shouldAdd = true
						// Remove this entry to avoid duplicates
						delete(uniqueEntries, identifier)
					}
				} else if strings.HasPrefix(key, "Private Key:") {
					privateKey := normalizePrivateKey(strings.TrimPrefix(key, "Private Key: "))
					identifier = "key:" + privateKey
					if _, exists := uniqueEntries[identifier]; exists {
						shouldAdd = true
						// Remove this entry to avoid duplicates
						delete(uniqueEntries, identifier)
					}
				} else if strings.HasPrefix(key, "Wallet:") || strings.HasPrefix(key, "Address:") {
					walletAddress := normalizeWalletAddress(strings.TrimPrefix(
						strings.TrimPrefix(key, "Wallet: "),
						"Address: "))
					identifier = "addr:" + walletAddress
					if _, exists := uniqueEntries[identifier]; exists {
						shouldAdd = true
						// Remove this entry to avoid duplicates
						delete(uniqueEntries, identifier)
					}
				}
			}
			
			// If no unique entry matches, try the content fingerprint
			if !shouldAdd {
				identifier = "context:" + createContentFingerprint(result.Content, result.AssociatedKeys)
				if _, exists := uniqueEntries[identifier]; !exists {
					continue
				}
				
				// Remove this entry from uniqueEntries to avoid duplicates
				delete(uniqueEntries, identifier)
			}
		}
		
		// Add the result to the deduplicated list since we've verified it's unique
		deduplicated = append(deduplicated, result)
	}
	
	return deduplicated
}

// normalizeSeedPhrase standardizes seed phrases for comparison
func normalizeSeedPhrase(phrase string) string {
	// Remove leading/trailing spaces and convert to lowercase
	normalized := strings.TrimSpace(strings.ToLower(phrase))

	// Handle multiline phrases (unlikely but possible)
	if strings.Contains(normalized, "\n") {
		normalized = strings.ReplaceAll(normalized, "\n", " ")
	}

	// Remove duplicate spaces
	for strings.Contains(normalized, "  ") {
		normalized = strings.ReplaceAll(normalized, "  ", " ")
	}

	return normalized
}

// normalizePrivateKey standardizes private keys for comparison
func normalizePrivateKey(key string) string {
	// Remove 0x prefix if present for Ethereum-style keys
	key = strings.TrimSpace(key)
	if strings.HasPrefix(key, "0x") {
		key = key[2:]
	}
	
	// Remove any (VERIFIED) marker
	key = strings.TrimSuffix(key, " (VERIFIED)")
	
	// Convert to lowercase for hex keys
	if len(key) == 64 && isHex(key) {
		key = strings.ToLower(key)
	}
	
	return key
}

// normalizeWalletAddress standardizes wallet addresses for comparison
func normalizeWalletAddress(address string) string {
	// Remove leading/trailing spaces
	address = strings.TrimSpace(address)
	
	// Remove any status markers
	address = strings.TrimSuffix(address, " (VERIFIED)")
	address = strings.TrimSuffix(address, " (DERIVED)")
	address = strings.TrimSuffix(address, " (DETERMINISTIC)")
	address = strings.TrimSuffix(address, " (Unverified)")
	address = strings.TrimSuffix(address, " (FORMAT EXAMPLE - not derived from key)")
	address = strings.TrimSuffix(address, " (DETERMINISTIC - not cryptographically verified)")
	address = strings.TrimSuffix(address, " (VERIFIED - derived from private key)")
	
	// For Ethereum addresses, convert to lowercase (checksum doesn't matter for deduplication)
	if strings.HasPrefix(address, "0x") && len(address) == 42 {
		return strings.ToLower(address)
	}
	
	return address
}

// isHex returns true if the string contains only hexadecimal characters
func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// createContentFingerprint creates a unique identifier for a set of associated keys
func createContentFingerprint(content string, keys []string) string {
	// Concatenate all keys into a single string and hash it
	allKeys := content + "|" + strings.Join(keys, "|")
	hash := sha256.Sum256([]byte(allKeys))
	return hex.EncodeToString(hash[:])
}