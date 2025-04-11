package scanner

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/grendel/godel/internal/wallet"
	"github.com/grendel/godel/pkg/crypto"
	"github.com/grendel/godel/pkg/fileutil"
	"github.com/grendel/godel/pkg/matcher"
	"github.com/grendel/godel/pkg/ui"
)

// ScanResult represents the results of a file scan
type ScanResult struct {
	ValidMatches    int
	IgnoredMatches  int
	FilesScanned    int
	FailedKeysByType map[string]int
}

// ProcessFiles scans and analyzes a list of files for cryptocurrency information
func ProcessFiles(files []string, maxSize int64, verbose bool) ScanResult {
	// Initialize color scheme for consistent formatting
	cs := ui.DefaultColorScheme()

	// Convert maxSize from MB to bytes (as expected by the pattern matcher)
	maxSizeBytes := maxSize * 1024 * 1024
	// Initialize the pattern matcher with the specified max file size
	patternMatcher := matcher.NewPatternMatcherWithConfig(maxSizeBytes)

	// Set up a progress reporting function
	patternMatcher.SetProgressReporting(func(lineNum int, totalBytes int64, processedBytes int64) {
		percentage := 0.0
		if totalBytes > 0 {
			percentage = float64(processedBytes) / float64(totalBytes) * 100
		}
		fmt.Printf("\r  Processing: %d lines | %.2f%% complete (%d/%d MB)",
			lineNum, percentage, processedBytes/(1024*1024), totalBytes/(1024*1024))
	})

	result := ScanResult{
		ValidMatches:    0,
		IgnoredMatches:  0,
		FilesScanned:    len(files),
		FailedKeysByType: make(map[string]int),
	}

	// Process each file
	for _, file := range files {
		cs.File.Printf("Analyzing: %s\n", filepath.Base(file))

		results, err := patternMatcher.AnalyzeFile(file)
		if err != nil {
			log.Printf("Error analyzing file %s: %v", file, err)
			continue
		}

		// Clear the progress line with a new line
		fmt.Println()

		// Count matches in this file
		fileValidMatches := 0
		fileNonMatches := 0

		// Filter out overlapping keys and non-matches
		filteredResults := matcher.DeduplicateResults(results)

		// First determine valid matches
		for _, result := range filteredResults {
			// Determine if this is a valid match
			isValidMatch := false

			// Wallet Keywords are valid if they have associated keys
			if result.Type == matcher.WalletContext ||
				result.Type == matcher.BitcoinContext ||
				result.Type == matcher.EthereumContext ||
				result.Type == matcher.SolanaContext ||
				result.Type == matcher.LitecoinContext ||
				result.Type == matcher.CardanoContext ||
				result.Type == matcher.MoneroContext ||
				result.Type == matcher.CryptoContextFound ||
				result.Type == matcher.WalletMnemonicFound ||
				result.Type == matcher.CryptoBackupFound {
				isValidMatch = len(result.AssociatedKeys) > 0
			} else {
				// All other types (Seed Phrases, Private Keys, Wallet Addresses) are valid by default
				// since they've already passed comprehensive validation
				isValidMatch = true
			}

			if isValidMatch {
				fileValidMatches++
			} else {
				fileNonMatches++
			}
		}

		result.ValidMatches += fileValidMatches
		result.IgnoredMatches += fileNonMatches

		// Display match count for this file
		if len(filteredResults) > 0 || (fileNonMatches > 0 && verbose) {
			if fileNonMatches > 0 {
				cs.Result.Printf("  Found %d matches", fileValidMatches)
				if verbose {
					cs.Result.Printf(" and %d non-matches", fileNonMatches)
				} else if fileNonMatches > 0 {
					cs.Result.Printf(" (%d items were filtered out)", fileNonMatches)
				}
				fmt.Println()
			} else {
				cs.Result.Printf("  Found %d matches\n", fileValidMatches)
			}

			// Display match details
			matchNumber := 0
			for _, matchResult := range filteredResults {
				// Determine if this is a valid match (for formatting)
				isValidMatch := true // All results in filteredResults should be valid

				matchNumber++

				// Print match header with appropriate formatting based on new format
				ui.PrintMatchHeader(cs, matchNumber, string(matchResult.Type), isValidMatch)

				// Show file and line information
				cs.Result.Print("File: ")
				cs.Path.Print(filepath.Base(file))
				cs.Result.Print(" Line: ")
				cs.Path.Printf("%d\n", matchResult.LineNumber)

				// Display confidence if available
				if matchResult.Probability > 0 {
					cs.Result.Print("Confidence: ")
					// Use color coding for confidence levels
					if matchResult.Probability >= 0.9 {
						cs.Success.Printf("%.0f%% (High)\n", matchResult.Probability*100)
					} else if matchResult.Probability >= 0.7 {
						cs.Key.Printf("%.0f%% (Medium)\n", matchResult.Probability*100)
					} else {
						cs.Error.Printf("%.0f%% (Low)\n", matchResult.Probability*100)
					}
				}

				fmt.Println()

				// Group information by crypto type
				cryptoTypes := make(map[matcher.CryptoType]map[string][]string)

				// Initialize the default crypto type if needed
				if matchResult.Type == matcher.SeedPhrase || matchResult.Type == matcher.PrivateKey {
					// For direct matches, use the crypto type from the result
					if matchResult.CryptoType == matcher.Unknown {
						cryptoTypes[matcher.Ethereum] = make(map[string][]string) // Use Ethereum as default instead of Generic
					} else {
						cryptoTypes[matchResult.CryptoType] = make(map[string][]string)
					}
				}

				// For direct matches (non-wallet keywords), add the match itself
				if matchResult.Type == matcher.SeedPhrase {
					if matchResult.CryptoType == matcher.Unknown {
						if cryptoTypes[matcher.Ethereum] == nil { // Use Ethereum instead of Generic
							cryptoTypes[matcher.Ethereum] = make(map[string][]string)
						}
						cryptoTypes[matcher.Ethereum]["Seed Phrase"] = append(cryptoTypes[matcher.Ethereum]["Seed Phrase"], matchResult.Content)
					} else {
						if cryptoTypes[matchResult.CryptoType] == nil {
							cryptoTypes[matchResult.CryptoType] = make(map[string][]string)
						}
						cryptoTypes[matchResult.CryptoType]["Seed Phrase"] = append(cryptoTypes[matchResult.CryptoType]["Seed Phrase"], matchResult.Content)
					}
				} else if matchResult.Type == matcher.PrivateKey {
					if matchResult.CryptoType == matcher.Unknown {
						if cryptoTypes[matcher.Ethereum] == nil { // Use Ethereum instead of Generic
							cryptoTypes[matcher.Ethereum] = make(map[string][]string)
						}
						cryptoTypes[matcher.Ethereum]["Private Key"] = append(cryptoTypes[matcher.Ethereum]["Private Key"], matchResult.Content)
					} else {
						if cryptoTypes[matchResult.CryptoType] == nil {
							cryptoTypes[matchResult.CryptoType] = make(map[string][]string)
						}
						cryptoTypes[matchResult.CryptoType]["Private Key"] = append(cryptoTypes[matchResult.CryptoType]["Private Key"], matchResult.Content)
					}
				} else if (matchResult.Type == matcher.WalletContext ||
					matchResult.Type == matcher.BitcoinContext ||
					matchResult.Type == matcher.EthereumContext ||
					matchResult.Type == matcher.SolanaContext ||
					matchResult.Type == matcher.LitecoinContext ||
					matchResult.Type == matcher.CardanoContext ||
					matchResult.Type == matcher.MoneroContext ||
					matchResult.Type == matcher.CryptoContextFound ||
					matchResult.Type == matcher.WalletMnemonicFound ||
					matchResult.Type == matcher.CryptoBackupFound) &&
					len(matchResult.AssociatedKeys) > 0 {
					// For wallet keywords, process associated keys by crypto type

					// Initialize crypto type for the keyword if it's known
					if matchResult.CryptoType != matcher.Unknown {
						if cryptoTypes[matchResult.CryptoType] == nil {
							cryptoTypes[matchResult.CryptoType] = make(map[string][]string)
						}
					}

					// Sort keys into categories by crypto type
					for _, key := range matchResult.AssociatedKeys {
						parts := strings.SplitN(key, ": ", 2)
						if len(parts) < 2 {
							continue
						}

						keyType := parts[0]
						keyValue := parts[1]

						// Determine the crypto type for this key if possible
						var keyCryptoType matcher.CryptoType

						// For seed phrases, we might not know the crypto type
						if strings.Contains(keyType, "Seed Phrase") {
							keyCryptoType = matcher.Unknown
						} else {
							// For private keys and wallet addresses, try to detect the type from the content
							// Try to extract crypto type from the key format
							if strings.HasPrefix(keyValue, "0x") && len(keyValue) >= 42 && len(keyValue) <= 66 {
								keyCryptoType = matcher.Ethereum
							} else if strings.HasPrefix(keyValue, "5K") || strings.HasPrefix(keyValue, "5J") ||
								strings.HasPrefix(keyValue, "K") || strings.HasPrefix(keyValue, "L") {
								keyCryptoType = matcher.Bitcoin
							} else if strings.HasPrefix(keyValue, "6") || strings.HasPrefix(keyValue, "T") {
								keyCryptoType = matcher.Litecoin
							} else if len(keyValue) == 64 && regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(keyValue) {
								// This could be Ethereum or Monero private key without 0x prefix
								if !strings.HasPrefix(keyValue, "0") {
									keyCryptoType = matcher.Ethereum
								} else {
									keyCryptoType = matcher.Monero
								}
							} else if len(keyValue) > 90 && strings.HasPrefix(keyValue, "4") {
								keyCryptoType = matcher.Monero
							} else if strings.HasPrefix(keyValue, "addr1") || strings.HasPrefix(keyValue, "stake1") {
								keyCryptoType = matcher.Cardano
							} else if strings.HasPrefix(keyValue, "r") && len(keyValue) < 36 {
								keyCryptoType = matcher.Ripple
							} else if len(keyValue) >= 46 && len(keyValue) <= 48 {
								// Possible Polkadot address
								keyCryptoType = matcher.Polkadot
							} else if strings.HasPrefix(keyValue, "cosmos") || strings.HasPrefix(keyValue, "cosmosvaloper") {
								keyCryptoType = matcher.Cosmos
							} else if len(keyValue) >= 32 && len(keyValue) <= 44 {
								// Could be a Solana address
								keyCryptoType = matcher.Solana
							} else {
								// If we can't determine the type, use Ethereum as fallback
								keyCryptoType = matcher.Ethereum
							}
						}

						// Use the detected crypto type, or the result's crypto type, or Unknown as a last resort
						if keyCryptoType == matcher.Unknown {
							if matchResult.CryptoType != matcher.Unknown {
								keyCryptoType = matchResult.CryptoType
							} else {
								keyCryptoType = matcher.Ethereum // Default to Ethereum
							}
						}

						// Initialize this crypto type's map if needed
						if cryptoTypes[keyCryptoType] == nil {
							cryptoTypes[keyCryptoType] = make(map[string][]string)
						}

						// Normalize key type for display
						displayType := "Unknown"
						if strings.Contains(keyType, "Seed Phrase") {
							displayType = "Seed Phrase"
						} else if strings.Contains(keyType, "Private Key") {
							displayType = "Private Key"
						} else if strings.Contains(keyType, "Wallet") || strings.Contains(keyType, "Address") {
							displayType = "Wallet"
						}

						// Add this key to the appropriate list
						cryptoTypes[keyCryptoType][displayType] = append(cryptoTypes[keyCryptoType][displayType], keyValue)
					}
				}

				// Now display the information organized by crypto type
				displayedAnyData := false

				// Get unique crypto types including parent keys + wallet pairs
				cryptoPairs := make(map[matcher.CryptoType]map[string]string)

				// First, organize keys with their corresponding wallets
				for cryptoType, typeData := range cryptoTypes {
					// Only process valid sections
					if len(typeData) == 0 {
						continue
					}

					// Initialize if needed
					if cryptoPairs[cryptoType] == nil {
						cryptoPairs[cryptoType] = make(map[string]string)
					}

					// Extract private keys and seed phrases
					var keys []string
					if phrases, ok := typeData["Seed Phrase"]; ok {
						for _, phrase := range phrases {
							keys = append(keys, "Seed Phrase: "+phrase)
						}
					}

					if privKeys, ok := typeData["Private Key"]; ok {
						for _, key := range privKeys {
							keys = append(keys, "Private Key: "+key)
						}
					}

					// Extract wallet addresses
					var wallets []string
					if addresses, ok := typeData["Wallet"]; ok {
						for _, address := range addresses {
							wallets = append(wallets, address)
						}
					}

					// Associate each key with a wallet if available
					for _, key := range keys {
						if len(wallets) > 0 {
							// Associate with the first wallet of this crypto type
							cryptoPairs[cryptoType][key] = wallets[0]
							// Remove the used wallet to prevent duplicates
							if len(wallets) > 1 {
								wallets = wallets[1:]
							}
						} else {
							// No wallet address available
							cryptoPairs[cryptoType][key] = ""
						}
					}

					// Add remaining wallets without keys
					for _, wallet := range wallets {
						// Create a placeholder key
						cryptoPairs[cryptoType]["Wallet Only: "+wallet] = wallet
					}

					// Remove duplicate wallet entries - sometimes we get duplicate wallets
					// associated with different keys
					seenWallets := make(map[string]bool)
					for key, walletAddr := range cryptoPairs[cryptoType] {
						if walletAddr != "" && seenWallets[walletAddr] && strings.HasPrefix(key, "Wallet Only:") {
							delete(cryptoPairs[cryptoType], key)
						} else if walletAddr != "" {
							seenWallets[walletAddr] = true
						}
					}
				}

				// Display each crypto type with individual key+wallet pairs
				for cryptoType, pairs := range cryptoPairs {
					// Skip empty sections
					if len(pairs) == 0 {
						continue
					}

					// Check if this section has any displayable content
					hasContent := false
					for key, _ := range pairs {
						// Skip the "Wallet Only" placeholders - we'll handle them separately
						if !strings.HasPrefix(key, "Wallet Only:") {
							hasContent = true
							break
						}
					}

					// If we only have wallet-only entries, we should still display them
					walletOnlyEntries := false
					if !hasContent {
						for key, _ := range pairs {
							if strings.HasPrefix(key, "Wallet Only:") {
								walletOnlyEntries = true
								break
							}
						}
						if !walletOnlyEntries {
							continue // Skip this crypto type if it has no content at all
						}
					}

					displayedAnyData = true

					// Display crypto type header
					cs.Result.Print("Type: ")
					if cryptoType == matcher.Unknown {
						cs.Key.Printf("Ethereum\n") // Default to Ethereum instead of Generic
					} else {
						cs.Key.Printf("%s\n", cryptoType)
					}

					// Display each key-wallet pair on its own line
					for key, walletAddr := range pairs {
						if strings.HasPrefix(key, "Wallet Only:") {
							// Display wallet-only entries
							parts := strings.SplitN(key, ": ", 2)
							if len(parts) >= 2 {
								cs.Key.Print("  - Wallet:      ")
								cs.Path.Println(parts[1])
							}
							continue
						}

						parts := strings.SplitN(key, ": ", 2)
						if len(parts) < 2 {
							continue
						}

						keyType := parts[0]
						keyValue := parts[1]

						// Print the key
						cs.Key.Printf("  - %s: ", keyType)
						cs.Path.Println(keyValue)

						// For seed phrases, derive and show the private key and wallet
						if keyType == "Seed Phrase" {
							// Derive private key and wallet address from seed phrase
							derivedPrivateKey, _, err := crypto.DeriveKeysFromBIP39(keyValue, "", crypto.CryptoType(cryptoType))
							if err == nil && derivedPrivateKey != "" {
								cs.Key.Print("    Private Key: ")
								cs.Path.Println(derivedPrivateKey)
							}

							// Derive and show wallet address
							derivedWallet := wallet.DeriveWalletFromKey(keyValue, cryptoType, true)
							if derivedWallet != "" {
								cs.Key.Print("    Wallet:      ")
								cs.Path.Println(derivedWallet)
							}
						} else if keyType == "Private Key" {
							// For private keys, derive and show the wallet address
							derivedWallet := wallet.DeriveWalletFromKey(keyValue, cryptoType, false)
							cs.Key.Print("    Wallet:      ")
							cs.Path.Println(derivedWallet)
						} else if walletAddr != "" {
							// Print the corresponding wallet if available
							cs.Key.Print("    Wallet:      ")
							cs.Path.Println(walletAddr)
						}
						// We no longer show validation errors - errors are tracked with counters instead
					}

					fmt.Println()
				}

				// Don't show empty results
				if !displayedAnyData && verbose {
					cs.Result.Println("  No valid crypto data found for this match.")
				}

				// Only add spacing between entries if we're showing them
				fmt.Println()
			}
		} else {
			cs.Result.Println("  No matches found")
		}
	}

	// Update failed validation counts
	for cryptoType, count := range matcher.ErrorCounts {
		result.FailedKeysByType[string(cryptoType)] = count
	}

	return result
}

// ScanDirectory scans a directory and processes files for crypto information
func ScanDirectory(dirPath string, recursive bool, threads int, maxSize int64, verbose bool) (*ScanResult, error) {
	// Validate directory path
	dirInfo, err := os.Stat(dirPath)
	if err != nil {
		return nil, fmt.Errorf("error accessing directory: %v", err)
	}
	
	if !dirInfo.IsDir() {
		return nil, fmt.Errorf("specified path is not a directory: %s", dirPath)
	}

	// Initialize the file scanner with the specified configuration
	// Convert maxSize from MB to bytes (as expected by the scanner)
	maxSizeBytes := maxSize * 1024 * 1024
	scanner := fileutil.NewScannerWithConfig(recursive, threads, maxSizeBytes)

	// Scan for files
	files, err := scanner.ScanDirectory(dirPath)
	if err != nil {
		return nil, fmt.Errorf("error scanning directory: %v", err)
	}

	// Process found files
	result := ProcessFiles(files, maxSize, verbose)
	
	return &result, nil
}