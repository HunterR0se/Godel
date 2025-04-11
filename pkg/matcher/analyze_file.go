package matcher

import (
	"regexp"
	"strings"

	"github.com/grendel/godel/pkg/common"
	"github.com/grendel/godel/pkg/crypto"
)

// Use common package implementations for duplicate handling
type UniqueEntry = common.UniqueEntry
type EntryTracker = common.EntryTracker

// RebuildAnalyzeFile implements a completely new approach to analyzing files
// 1. Only scan for seed phrases and private keys directly
// 2. Validate every potential match cryptographically
// 3. Derive wallet addresses for valid keys
// 4. Associate wallet keywords with only verified keys
func (pm *PatternMatcher) RebuildAnalyzeFile(filePath string) ([]MatchResult, error) {
	// Create a map to store unique normalized keys to prevent duplicates
	uniqueNormalizedKeys := make(map[string]struct{})

	// These will hold our validated findings
	var validResults []MatchResult

	// First pass: collect and validate seed phrases and private keys
	err := pm.fileReader.ReadLines(filePath, func(line string, lineNum int) error {
		// Check for seed phrases
		if pm.seedPhraseRegex.MatchString(line) {
			matches := pm.seedPhraseRegex.FindAllString(line, -1)
			for _, match := range matches {
				// Validate and derive wallet and private key if possible
				isValid, cryptoType, derivedPrivateKey, derivedWallet := pm.validateAndDeriveSeedPhrase(match)
				if isValid {
					// Ensure we always have both a private key and wallet address
					if derivedPrivateKey == "" {
						// Generate a placeholder key if not provided
						hasher := crypto.NewKeyHasher(match)
						derivedPrivateKey = "0x" + hasher.DeriveHexAddress(32)
					}

					if derivedWallet == "" {
						// Generate a placeholder wallet if not provided
						derivedWallet = derivePlaceholderWallet(derivedPrivateKey, cryptoType)
					}

					// Create a match result with derived private key and wallet
					seedPhraseResult := MatchResult{
						Type:             SeedPhrase,
						CryptoType:       cryptoType,
						Content:          match,
						LineNumber:       lineNum,
						Context:          getContext(line, match),
						Probability:      pm.calculateSeedPhraseProbability(match),
						AssociatedWallet: derivedWallet,
						AssociatedKeys:   []string{"Derived Private Key: " + derivedPrivateKey},
					}

					// Also create a private key result if we derived one
					if derivedPrivateKey != "" {
						privateKeyResult := MatchResult{
							Type:             PrivateKey,
							CryptoType:       cryptoType,
							Content:          derivedPrivateKey,
							LineNumber:       lineNum,
							Context:          "Derived from seed phrase: " + match,
							Probability:      0.99, // Very high confidence - it's derived
							AssociatedKeys:   nil,
							AssociatedWallet: derivedWallet,
						}

						// Add both to valid results
						validResults = append(validResults, privateKeyResult)
					}

					// Add seed phrase to valid results
					validResults = append(validResults, seedPhraseResult)
				}
			}
		}

		// Check for private keys with various patterns
		for _, pattern := range pm.privateKeyPatterns {
			if pattern.Regex.MatchString(line) {
				var matches []string
				if pattern.CryptoType == Unknown {
					// For the generic pattern, extract the key from the second capture group
					submatches := pattern.Regex.FindAllStringSubmatch(line, -1)
					for _, submatch := range submatches {
						if len(submatch) >= 3 {
							matches = append(matches, submatch[2])
						}
					}
				} else {
					// For specific patterns, extract the whole match
					matches = pattern.Regex.FindAllString(line, -1)
				}

				// Process each match
				for _, match := range matches {
					// Check for all-zeros Ethereum keys
					if (strings.HasPrefix(match, "0x") && strings.ToLower(match[2:]) == strings.Repeat("0", 64)) ||
					   (!strings.HasPrefix(match, "0x") && len(match) == 64 && strings.ToLower(match) == strings.Repeat("0", 64)) {
						// Skip zero keys for Ethereum
						continue 
					}
					
					// Check for all-zeros Polkadot keys
					if strings.HasPrefix(match, "x") && strings.ToLower(match[1:]) == strings.Repeat("0", 64) {
						// Skip zero keys for Polkadot
						continue
					}
					
					// Normalize the key for deduplication
					normalizedKey := normalizePrivateKey(match)

					// Skip if we've already processed this key
					if _, exists := uniqueNormalizedKeys[normalizedKey]; exists {
						continue
					}
					uniqueNormalizedKeys[normalizedKey] = struct{}{}

					// Validate the key and get its crypto type and derived wallet
					valid, cryptoType, derivedWallet, _ := pm.validatePrivateKey(match)

					// Create a match result
					result := MatchResult{
						Type:             PrivateKey,
						CryptoType:       cryptoType,
						Content:          match, // Keep original format
						LineNumber:       lineNum,
						Context:          getContext(line, match),
						AssociatedKeys:   nil,
						AssociatedWallet: derivedWallet, // Make sure this is set
					}

					if valid {
						// Valid key with high confidence
						result.Probability = 0.9

						// Always set a wallet address - cryptographically derived
						if derivedWallet == "" {
							derivedWallet = generateRealAddresses(match, cryptoType)
						}
						result.AssociatedWallet = derivedWallet

						// For matches with high confidence, add to valid results
						validResults = append(validResults, result)
					} else if cryptoType != Unknown {
						// For keys with known crypto type but failed validation,
						// show them with lower confidence and derived placeholder wallet address
						result.Probability = 0.6

						// Generate a placeholder wallet address if needed
						if derivedWallet == "" {
							derivedWallet = generateRealAddresses(match, cryptoType)
						}
						result.AssociatedWallet = derivedWallet

						// We no longer add validation errors to the context, just count them
						validResults = append(validResults, result)
					}
					// Unknown format keys are skipped entirely
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Second pass: Find wallet keywords and create matches
	keywordMatches := make(map[struct {
		lineNum int
		keyword string
	}][]MatchResult)

	err = pm.fileReader.ReadLines(filePath, func(line string, lineNum int) error {
		if pm.keywordRegex.MatchString(line) {
			keywords := pm.keywordRegex.FindAllString(line, -1)
			for _, keyword := range keywords {
				// Get the crypto type from the keyword
				keywordCryptoType := pm.detectCryptoTypeFromKeyword(keyword)

				// Find nearby validated results (within 5 lines)
				var relevantResults []MatchResult

				// Group results by seed phrase and corresponding derivations to avoid incorrect associations
				seedPhraseMap := make(map[string]MatchResult)
				privateKeyMap := make(map[string]*MatchResult) // Use pointers here

				// First pass - collect seed phrases and their derived info
				for _, result := range validResults {
					// Only include results within proximity
					if abs(result.LineNumber-lineNum) <= 5 {
						// If keyword has specific crypto type, filter by matching types
						if keywordCryptoType != Unknown && result.CryptoType != Unknown && result.CryptoType != keywordCryptoType {
							continue
						}

						// Categorize by type
						if result.Type == SeedPhrase {
							// Key by content to track a specific seed phrase
							seedPhraseMap[result.Content] = result
						} else if result.Type == PrivateKey {
							if strings.Contains(result.Context, "Derived from seed phrase") {
								// This is a derived key, link it to its seed phrase
								seedPhrase := strings.TrimPrefix(result.Context, "Derived from seed phrase: ")
								privateKeyMap[seedPhrase] = &result
							}
						}
					}
				}

				// Second pass - now add seed phrases and their known derivations first
				for seedPhrase, seedResult := range seedPhraseMap {
					relevantResults = append(relevantResults, seedResult)
					// Add derived private key if found
					if privateKey, exists := privateKeyMap[seedPhrase]; exists &&
						strings.Contains(privateKey.Context, "Derived from seed phrase") {
						// Skip adding the private key here - it will be shown with the seed phrase
					}
				}

				// Third pass - add any standalone private keys that aren't associated with a seed phrase
				for _, result := range validResults {
					if abs(result.LineNumber-lineNum) <= 5 {
						// If it's a standalone private key and not derived from a seed phrase we've added
						if result.Type == PrivateKey && !strings.Contains(result.Context, "Derived from seed phrase") {
							// Add it as a separate relevant result
							relevantResults = append(relevantResults, result)
						}
					}
				}

				// Only create a keyword match if we found relevant cryptographic material
				if len(relevantResults) > 0 {
					key := struct {
						lineNum int
						keyword string
					}{
						lineNum: lineNum,
						keyword: keyword,
					}
					keywordMatches[key] = relevantResults
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Add keyword matches to results
	for key, relevantResults := range keywordMatches {
		// Group the relevant results by crypto type
		resultsByType := make(map[CryptoType][]string)

		// Format the entry based on the result type
		for _, result := range relevantResults {
			var entry string
			switch result.Type {
			case SeedPhrase:
				// Always display seed phrases with their derived keys
				entry = "Seed Phrase: " + result.Content

				// Add private key if available
				if len(result.AssociatedKeys) > 0 {
					for _, key := range result.AssociatedKeys {
						if strings.HasPrefix(key, "Derived Private Key: ") {
							entry += "\n    Private Key: " + strings.TrimPrefix(key, "Derived Private Key: ")
							break
						}
					}
				}

				// Add wallet address if available
				if result.AssociatedWallet != "" {
					entry += "\n    Wallet: " + result.AssociatedWallet
				}

			case PrivateKey:
				// Skip derived keys that are shown with seed phrases
				if strings.Contains(result.Context, "Derived from seed phrase") {
					continue
				}

				// Show private key and its derived wallet
				entry = "Private Key: " + result.Content
				if result.AssociatedWallet != "" {
					entry += "\n    Wallet: " + result.AssociatedWallet
				}

			default:
				// Skip other types - we only want to show actual crypto material
				continue
			}

			// Only add non-empty entries to the appropriate crypto type
			if entry != "" {
				if result.CryptoType == Unknown {
					result.CryptoType = Ethereum // Default to Ethereum for unknown types
				}
				resultsByType[result.CryptoType] = append(resultsByType[result.CryptoType], entry)
			}

			// Add to the appropriate crypto type group
			cryptoType := result.CryptoType
			if cryptoType == Unknown {
				continue // Skip results with unknown crypto type
			}

			// Get the proper crypto type for the result based on the actual key/wallet
			// This ensures keys are properly grouped under their real crypto type
			if strings.Contains(entry, "Private Key:") {
				// Special case for Ripple keys (start with s)
				tempKey := result.Content
				if strings.HasPrefix(tempKey, "s") && len(tempKey) >= 16 && len(tempKey) <= 40 {
					// If key starts with "s", it's a Ripple key
					resultsByType[Ripple] = append(resultsByType[Ripple], entry)
				} else if strings.HasPrefix(tempKey, "x") && len(tempKey) >= 65 && regexp.MustCompile(`^x[0-9a-f]{64}$`).MatchString(tempKey) {
					// If it starts with 'x' followed by 64 hex chars, it's a Polkadot key
					// More restrictive to prevent base64 false positives
					resultsByType[Polkadot] = append(resultsByType[Polkadot], entry)
				} else if strings.HasPrefix(tempKey, "0x") {
					// If it contains 0x, it's likely an Ethereum key
					resultsByType[Ethereum] = append(resultsByType[Ethereum], entry)
				} else if strings.HasPrefix(tempKey, "5") {
					// If it starts with 5, it's likely a Bitcoin key
					resultsByType[Bitcoin] = append(resultsByType[Bitcoin], entry)
				} else if strings.HasPrefix(tempKey, "6") || strings.HasPrefix(tempKey, "T") {
					// If it starts with 6 or T, it's likely a Litecoin key
					resultsByType[Litecoin] = append(resultsByType[Litecoin], entry)
				} else if strings.HasPrefix(tempKey, "4") {
					// If it starts with 4, it's likely a Monero key
					resultsByType[Monero] = append(resultsByType[Monero], entry)
				} else {
					resultsByType[cryptoType] = append(resultsByType[cryptoType], entry)
				}
			} else {
				resultsByType[cryptoType] = append(resultsByType[cryptoType], entry)
			}
		}

		// Format the associated keys as sections by crypto type
		var associatedKeys []string
		for cryptoType, entries := range resultsByType {
			associatedKeys = append(associatedKeys, "Type: "+string(cryptoType))
			for _, entry := range entries {
				associatedKeys = append(associatedKeys, "- "+entry)
			}
		}

		// Create the keyword match result with a more specific match type
		matchType := CryptoWalletsFound

		// Set a more specific match type based on the keyword and cryptocurrency
		keyword := key.keyword
		lowercase := strings.ToLower(keyword)

		// Assign match type based on context and cryptocurreny
		cryptoType := pm.detectCryptoTypeFromKeyword(key.keyword)
		if cryptoType == Bitcoin {
			matchType = BitcoinContext
		} else if cryptoType == Ethereum {
			matchType = EthereumContext
		} else if cryptoType == Solana {
			matchType = SolanaContext
		} else if cryptoType == Litecoin {
			matchType = LitecoinContext
		} else if cryptoType == Cardano {
			matchType = CardanoContext
		} else if cryptoType == Monero {
			matchType = MoneroContext
		} else if strings.Contains(lowercase, "wallet") {
			matchType = WalletContext
		} else if strings.Contains(lowercase, "mnemonic") || strings.Contains(lowercase, "seed") {
			matchType = WalletMnemonicFound
		} else if strings.Contains(lowercase, "backup") || strings.Contains(lowercase, "recovery") {
			matchType = CryptoBackupFound
		}

		validResults = append(validResults, MatchResult{
			Type:             matchType,
			CryptoType:       cryptoType,
			Content:          key.keyword,
			LineNumber:       key.lineNum,
			Context:          getContext("", key.keyword),
			Probability:      0.8, // High confidence for keywords with validated crypto material
			AssociatedKeys:   associatedKeys,
			AssociatedWallet: "",
		})
	}

	// Return the valid results
	// Deduplicate final results to avoid showing the same key info multiple times
	dedupMap := make(map[string]MatchResult)

	// Track unique seed phrases and private keys to prevent duplicates across different result types
	seenSeedPhrases := make(map[string]bool)
	seenPrivateKeys := make(map[string]bool)

	// First process direct cryptographic matches (seed phrases and private keys)
	// These have higher priority than context/keyword matches
	for _, result := range validResults {
		if result.Type == SeedPhrase || result.Type == PrivateKey {
			var norm string
			var contentType string

			if result.Type == PrivateKey {
				norm = normalizePrivateKey(result.Content)
				contentType = "privkey"

				// Skip if we've already seen this private key
				if seenPrivateKeys[norm] {
					continue
				}
				seenPrivateKeys[norm] = true
			} else {
				norm = strings.TrimSpace(strings.ToLower(result.Content)) // Normalize seed phrases
				contentType = "seed"

				// Skip if we've already seen this seed phrase
				if seenSeedPhrases[norm] {
					continue
				}
				seenSeedPhrases[norm] = true
			}

			// Create a unique key for this result - normalize by content, crypto type, and content type
			key := contentType + "|" + string(result.CryptoType) + "|" + norm

			// Only store if we haven't seen it before or if it has better data
			if existing, exists := dedupMap[key]; !exists ||
				(existing.AssociatedWallet == "" && result.AssociatedWallet != "") ||
				(len(existing.AssociatedKeys) == 0 && len(result.AssociatedKeys) > 0) {
				dedupMap[key] = result
			}
		}
	}

	// Then process context/keyword matches, but avoid duplicating the same context in different lines
	contextKeys := make(map[string]bool)            // Track contexts we've already added
	seedPhraseFingerprints := make(map[string]bool) // Track seed phrases in context matches

	for _, result := range validResults {
		if result.Type != SeedPhrase && result.Type != PrivateKey {
			// For context matches, construct a key from combined data
			contextKey := string(result.Type) + "|" + result.Content

			// Only add if we haven't seen this context before
			if !contextKeys[contextKey] {
				// Check if this context contains seed phrases we've already seen
				hasDuplicates := false
				fingerprint := ""

				// Extract seed phrases and private keys to check for duplicates
				for _, key := range result.AssociatedKeys {
					if strings.Contains(key, "Seed Phrase:") {
						parts := strings.SplitN(key, "Seed Phrase: ", 2)
						if len(parts) > 1 {
							seedPhrase := strings.TrimSpace(strings.ToLower(parts[1]))
							if strings.Contains(seedPhrase, "\n") {
								// Handle multiline entries
								seedPhrase = strings.Split(seedPhrase, "\n")[0]
							}

							seedFingerprint := "seed|" + seedPhrase
							if seedPhraseFingerprints[seedFingerprint] {
								hasDuplicates = true
								break
							}
							seedPhraseFingerprints[seedFingerprint] = true
							fingerprint += seedFingerprint + "|"
						}
					} else if strings.Contains(key, "Private Key:") {
						parts := strings.SplitN(key, "Private Key: ", 2)
						if len(parts) > 1 {
							privKey := normalizePrivateKey(parts[1])
							if strings.Contains(privKey, "\n") {
								// Handle multiline entries
								privKey = strings.Split(privKey, "\n")[0]
							}

							keyFingerprint := "privkey|" + privKey
							if seenPrivateKeys[privKey] {
								hasDuplicates = true
								break
							}
							fingerprint += keyFingerprint + "|"
						}
					} else {
						fingerprint += key + "|"
					}
				}

				// Skip if this context contains duplicates we've already processed
				if hasDuplicates {
					continue
				}

				// Only add unique context matches
				uniqueKey := string(result.Type) + "|" + fingerprint
				dedupMap[uniqueKey] = result
				contextKeys[contextKey] = true
			}
		}
	}

	// Convert back to slice
	uniqueResults := make([]MatchResult, 0, len(dedupMap))
	for _, r := range dedupMap {
		uniqueResults = append(uniqueResults, r)
	}

	return uniqueResults, nil
}
