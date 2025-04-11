package matcher

import (
	"regexp"
	"strings"

	"github.com/grendel/godel/pkg/crypto"
	"github.com/grendel/godel/pkg/fileutil"
	"github.com/grendel/godel/pkg/patterns"
)

// MatchType represents the type of match found
type MatchType string

const (
	SeedPhrase          MatchType = "Seed Phrase Found"
	PrivateKey          MatchType = "Private Key Found"
	WalletAddress       MatchType = "Wallet Address Found"
	WalletContext       MatchType = "Wallets Found"
	BitcoinContext      MatchType = "Bitcoin Wallets Found"
	EthereumContext     MatchType = "Ethereum Wallets Found"
	SolanaContext       MatchType = "Solana Wallets Found"
	LitecoinContext     MatchType = "Litecoin Wallets Found"
	CardanoContext      MatchType = "Cardano Wallets Found"
	MoneroContext       MatchType = "Monero Wallets Found"
	BitcoinWalletFound  MatchType = "Bitcoin Wallet Found"
	EthereumWalletFound MatchType = "Ethereum Wallet Found"
	SolanaWalletFound   MatchType = "Solana Wallet Found"
	LitecoinWalletFound MatchType = "Litecoin Wallet Found"
	CardanoWalletFound  MatchType = "Cardano Wallet Found"
	MoneroWalletFound   MatchType = "Monero Wallet Found"
	CryptoWalletsFound  MatchType = "Crypto Wallets Found"
	CryptoContextFound  MatchType = "Crypto Wallets Found"
	WalletMnemonicFound MatchType = "Wallet Mnemonic Found"
	CryptoBackupFound   MatchType = "Crypto Backup Found"
)

// Use crypto.CryptoType for consistent type definitions
type CryptoType = crypto.CryptoType

// Reuse the CryptoType constants from the crypto package
const (
	Unknown  = crypto.Unknown
	Ethereum = crypto.Ethereum
	Bitcoin  = crypto.Bitcoin
	Solana   = crypto.Solana
	Monero   = crypto.Monero
	Litecoin = crypto.Litecoin
	Cardano  = crypto.Cardano
	Ripple   = crypto.Ripple
	Polkadot = crypto.Polkadot
	Cosmos   = crypto.Cosmos
)

// MatchResult represents a match found in a file
type MatchResult struct {
	Type             MatchType  // Type of match (seed phrase, private key, etc.)
	CryptoType       CryptoType // Type of cryptocurrency (if applicable)
	Content          string     // The matched content
	LineNumber       int        // Line number where the match was found
	FilePath         string     // Path to the file where the match was found
	Context          string     // Surrounding text for context
	Probability      float64    // Confidence level (0.0-1.0)
	AssociatedKeys   []string   // Related seed phrases or private keys found
	AssociatedWallet string     // Derived wallet address from private key (if applicable)
}

// KeyPattern defines a pattern for matching a specific type of cryptocurrency key
type KeyPattern struct {
	Regex      *regexp.Regexp
	CryptoType CryptoType
}

// PatternMatcher is responsible for matching patterns in text
type PatternMatcher struct {
	seedPhraseRegex    *regexp.Regexp
	privateKeyPatterns []KeyPattern
	keywordRegex       *regexp.Regexp
	fileReader         *fileutil.FileReader
	wordList           map[string]bool
}

// ValidateRippleKey performs checks on a Ripple/XRP private key
func (pm *PatternMatcher) ValidateRippleKey(key string) bool {
	return pm.validateRippleKey(key)
}

// ValidateRippleAddress performs checks on a Ripple/XRP address
func (pm *PatternMatcher) ValidateRippleAddress(address string) bool {
	// Use our internal validation function from matcher.go
	return pm.validateRippleAddress(address)
}

// Maximum number of keys to display per type for cleaner output
const maxKeysPerType = 2

// NewPatternMatcher creates a new pattern matcher
func NewPatternMatcher() *PatternMatcher {
	return NewPatternMatcherWithConfig(1024) // Default to 1GB max file size
}

// NewPatternMatcherWithConfig creates a new pattern matcher with custom configuration
func NewPatternMatcherWithConfig(maxFileSizeMB int64) *PatternMatcher {
	// Initialize seed phrase regex - strict format
	// Match exactly 12, 15, 18, 21, or 24 words (not 11, 13, etc.)
	seedPhraseRegex := regexp.MustCompile(
		`(\b\w+\b\s+){11}\b\w+\b|` + // 12 words
			`(\b\w+\b\s+){14}\b\w+\b|` + // 15 words
			`(\b\w+\b\s+){17}\b\w+\b|` + // 18 words
			`(\b\w+\b\s+){20}\b\w+\b|` + // 21 words
			`(\b\w+\b\s+){23}\b\w+\b`) // 24 words

	// Initialize private key patterns for different cryptocurrencies
	privateKeyPatterns := []KeyPattern{
		// Ethereum private key format: 0x followed by 64 hex chars
		{regexp.MustCompile(`(?i)0x[a-f0-9]{64}`), Ethereum},

		// Bitcoin private key in WIF format: starts with 5, K or L, usual length 51-52 (but we also accept truncated keys)
		{regexp.MustCompile(`(?i)[5KL][1-9A-HJ-NP-Za-km-z]{50,51}`), Bitcoin},

		// Litecoin private key in WIF format: starts with 6, T
		{regexp.MustCompile(`(?i)[6T][1-9A-HJ-NP-Za-km-z]{50,51}`), Litecoin},

		// Monero private key: 64 hex characters (spend key) or 32-byte hex string
		{regexp.MustCompile(`(?i)(^|[^a-f0-9])[0-9a-f]{64}([^a-f0-9]|$)`), Monero},

		// Solana private key format: base58 encoded, typically ~88 chars
		{regexp.MustCompile(`(?i)[1-9A-HJ-NP-Za-km-z]{87,88}`), Solana},

		// Cardano extended private key format
		{regexp.MustCompile(`(?i)(ed25519e?_sk|xprv)[1-9A-HJ-NP-Za-km-z]{96,107}`), Cardano},

		// Cardano path-based key format
		{regexp.MustCompile(`(?i)(addr_sk|stake_sk)[a-z0-9]{50,}`), Cardano},

		// Ripple/XRP private key format - typically starts with 's'
		{regexp.MustCompile(`(?i)s[1-9A-HJ-NP-Za-km-z]{28,29}`), Ripple},

		// Polkadot private key format - 'x' prefix + 64 hex - more variants
		{regexp.MustCompile(`(?i)x[0-9a-f]{64}`), Polkadot},

		// Polkadot SS58 format private key - must be more strict to avoid base64 false positives
		{regexp.MustCompile(`(?i)^[1-9A-HJ-NP-Za-km-z]{47,48}$`), Polkadot},

		// Cosmos/ATOM mnemonic key
		{regexp.MustCompile(`(?i)(cosmosvaloper|cosmos)[1-9A-HJ-NP-Za-km-z]{38,45}`), Cosmos},

		// Cosmos private key format - hex format or bech32
		{regexp.MustCompile(`(?i)cosmos1[a-z0-9]{38,}`), Cosmos},

		// Private key context pattern - for detecting labeled keys
		// This pattern finds context like "private key: KEY"
		// We'll use Unknown type and determine actual type during validation
		{regexp.MustCompile(`(?i)(private\s*key|seed|mnemonic)[:\s]+["']?([a-zA-Z0-9]{50,})["']?`), Unknown},
	}

	// Keywords related to wallets
	walletKeywords := []string{
		// General wallet terms
		"wallet", "private key", "secret key", "seed phrase", "recovery phrase",
		"mnemonic", "passphrase", "backup phrase", "seed words",

		// Cryptocurrency terms
		"bitcoin", "btc", "ethereum", "eth", "solana", "sol", "binance", "bnb",
		"tether", "usdt", "ripple", "xrp", "cardano", "ada", "dogecoin", "doge",
		"polkadot", "dot", "uniswap", "uni", "litecoin", "ltc", "monero", "xmr",

		// Wallet software/services
		"metamask", "solflare", "exodus", "trust wallet", "ledger", "trezor",
		"coinbase", "binance wallet", "blockchain.com", "phantom", "myetherwallet",
		"electrum", "jaxx", "atomic wallet", "safepal", "crypto.com", "cake wallet",
	}
	keywordPattern := "(?i)(" + strings.Join(walletKeywords, "|") + ")"
	keywordRegex := regexp.MustCompile(keywordPattern)

	// Initialize word list for validating seed phrases
	wordList := patterns.GetBIP39WordList()

	return &PatternMatcher{
		seedPhraseRegex:    seedPhraseRegex,
		privateKeyPatterns: privateKeyPatterns,
		keywordRegex:       keywordRegex,
		fileReader:         fileutil.NewFileReaderWithConfig(maxFileSizeMB * 1024 * 1024),
		wordList:           wordList,
	}
}

// AnalyzeFile analyzes a file for patterns
func (pm *PatternMatcher) AnalyzeFile(filePath string) ([]MatchResult, error) {
	// Use the rebuilt implementation that properly validates and links results
	return pm.RebuildAnalyzeFile(filePath)
}

// SetProgressReporting sets a progress reporting function
func (pm *PatternMatcher) SetProgressReporting(statusFunc func(lineNum int, totalBytes int64, processedBytes int64)) {
	// Pass the status update function to the file reader
	pm.fileReader.SetStatusUpdateFunc(statusFunc)
}

// detectCryptoTypeFromKey identifies the cryptocurrency type from its key format
func (pm *PatternMatcher) detectCryptoTypeFromKey(key string) CryptoType {
	// Ethereum private key format: 0x followed by 64 hex chars, or just 64 hex chars
	if regexp.MustCompile(`^(?:0x)?[a-fA-F0-9]{64}$`).MatchString(key) {
		// Validate it's a proper Ethereum key format (hexadecimal)
		if pm.validateEthereumKey(key) {
			return Ethereum
		}
	}

	// Bitcoin private key in WIF format: starts with 5, K or L, followed by base58 chars (about 51-52 chars total)
	if regexp.MustCompile(`^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$`).MatchString(key) {
		// Validate it's a proper Bitcoin WIF key format (specific formats and checksum)
		if pm.validateBitcoinWIF(key) {
			return Bitcoin
		}
	}

	// Litecoin private key in WIF format: starts with 6, T
	if regexp.MustCompile(`^[6T][1-9A-HJ-NP-Za-km-z]{50,51}$`).MatchString(key) {
		// Validate it's a proper Litecoin WIF key format
		if pm.validateLitecoinWIF(key) {
			return Litecoin
		}
	}

	// Monero private key: 64 hex characters
	if regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(key) && !strings.HasPrefix(key, "0x") {
		// Validate it's a proper Monero key format
		if pm.validateMoneroKey(key) {
			return Monero
		}
	}

	// Solana base58 private key format (typically around 88 chars)
	if regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{87,88}$`).MatchString(key) {
		// Validate it's a proper Solana key format
		if pm.validateSolanaKey(key) {
			return Solana
		}
	}

	// Cardano extended private key format
	if regexp.MustCompile(`^(ed25519e?_sk|xprv)[1-9A-HJ-NP-Za-km-z]{96,107}$`).MatchString(key) ||
		regexp.MustCompile(`^(addr_sk|stake_sk)[a-z0-9]{50,}$`).MatchString(key) {
		// Validate it's a proper Cardano key format
		if pm.validateCardanoKey(key) {
			return Cardano
		}
	}

	// Ripple/XRP private key format - typically starts with 's'
	if regexp.MustCompile(`^s[1-9A-HJ-NP-Za-km-z]{28,29}$`).MatchString(key) {
		// Validate it's a proper Ripple key format
		if pm.validateRippleKey(key) {
			return Ripple
		}
	}

	// Polkadot private key format - can be hex with x prefix or SS58 format
	if regexp.MustCompile(`^x[0-9a-f]{64}$`).MatchString(key) ||
		regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{47,48}$`).MatchString(key) {
		// Validate it's a proper Polkadot key format
		if pm.validatePolkadotKey(key) {
			return Polkadot
		}
	}

	// Cosmos/ATOM private key or address format
	if regexp.MustCompile(`^(cosmosvaloper|cosmos)[1-9A-HJ-NP-Za-km-z]{38,45}$`).MatchString(key) ||
		regexp.MustCompile(`^cosmos1[a-z0-9]{38,}$`).MatchString(key) {
		// Validate it's a proper Cosmos key format
		if pm.validateCosmosKey(key) {
			return Cosmos
		}
	}

	return Unknown
}

// validateEthereumKey performs additional checks on an Ethereum private key
func (pm *PatternMatcher) validateEthereumKey(key string) bool {
	// Strip 0x prefix if present
	if strings.HasPrefix(key, "0x") {
		key = key[2:]
	}

	// Basic validation: must be 64 hex characters exactly
	if len(key) != 64 {
		return false
	}

	// Validate that it's a valid hex string
	for _, c := range key {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}

	// A valid Ethereum key must not be all zeros and should be less than the curve order
	// (simplified check)
	if strings.ToLower(key) == strings.Repeat("0", 64) {
		return false
	}

	// Check if it's less than the secp256k1 curve order
	if strings.ToLower(key) > "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141" {
		return false
	}

	return true
}

// validateBitcoinWIF performs checks on a Bitcoin WIF private key
func (pm *PatternMatcher) validateBitcoinWIF(key string) bool {
	// Basic validation: the prefix indicates the network
	prefix := key[0]

	// Validate the length and prefix
	switch prefix {
	case '5': // Uncompressed key for mainnet
		if len(key) != 51 {
			return false
		}
	case 'K', 'L': // Compressed key for mainnet
		if len(key) != 52 {
			return false
		}
	default:
		return false
	}

	// Check if it contains only valid base58 characters
	for _, c := range key {
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return false
		}
		// Base58 only includes these characters
		if !((c >= '1' && c <= '9') || (c >= 'A' && c <= 'H') || (c >= 'J' && c <= 'N') ||
			(c >= 'P' && c <= 'Z') || (c >= 'a' && c <= 'k') || (c >= 'm' && c <= 'z')) {
			return false
		}
	}

	return true
}

// validateSolanaKey performs checks on a Solana private key
func (pm *PatternMatcher) validateSolanaKey(key string) bool {
	// Basic validation for Solana key format
	// Solana uses ed25519 keypairs which are typically encoded in base58

	// Check if it's a valid base58 string
	for _, c := range key {
		// Base58 doesn't include: 0, O, I, l
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return false
		}
	}

	// Simple length check - full private keys in Solana are typically around 88 chars in base58
	return len(key) >= 87 && len(key) <= 88
}

// detectCryptoTypeFromAddress identifies the cryptocurrency type from an address format
func (pm *PatternMatcher) detectCryptoTypeFromAddress(address string) CryptoType {
	// Ethereum address: 0x followed by 40 hex chars
	if regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`).MatchString(address) {
		// Validate it's a proper Ethereum address (checksum if mixed case)
		if pm.validateEthereumAddress(address) {
			return Ethereum
		}
	}

	// Bitcoin address: P2PKH (starts with 1), P2SH (starts with 3), or Bech32 (starts with bc1)
	if regexp.MustCompile(`^(1[1-9A-HJ-NP-Za-km-z]{25,34}|3[1-9A-HJ-NP-Za-km-z]{25,34}|bc1[a-zA-Z0-9]{25,90})$`).MatchString(address) {
		// Validate it's a proper Bitcoin address format
		if pm.validateBitcoinAddress(address) {
			return Bitcoin
		}
	}

	// Litecoin address: P2PKH (starts with L), P2SH (starts with M), or Bech32 (starts with ltc1)
	if regexp.MustCompile(`^(L[1-9A-HJ-NP-Za-km-z]{25,34}|M[1-9A-HJ-NP-Za-km-z]{25,34}|ltc1[a-zA-Z0-9]{25,64})$`).MatchString(address) {
		// Validate it's a proper Litecoin address format
		if pm.validateLitecoinAddress(address) {
			return Litecoin
		}
	}

	// Monero address: starts with 4, typically 95-106 characters
	if regexp.MustCompile(`^4[0-9A-Za-z]{94,105}$`).MatchString(address) {
		// Validate it's a proper Monero address format
		if pm.validateMoneroAddress(address) {
			return Monero
		}
	}

	// Solana address: base58 encoded, typically 32-44 chars
	if regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{32,44}$`).MatchString(address) {
		// Validate it's a proper Solana address format
		if pm.validateSolanaAddress(address) {
			return Solana
		}
	}

	// Cardano address: starts with addr1, stake1, or similar prefixes
	if regexp.MustCompile(`^(addr1|stake1)[0-9a-z]{50,120}$`).MatchString(address) {
		// Validate it's a proper Cardano address format
		if pm.validateCardanoAddress(address) {
			return Cardano
		}
	}

	// Ripple/XRP address: typically starts with r, followed by 25-35 characters
	if regexp.MustCompile(`^r[0-9a-zA-Z]{24,34}$`).MatchString(address) {
		// Validate it's a proper Ripple address format
		if pm.validateRippleAddress(address) {
			return Ripple
		}
	}

	// Polkadot address: typically a SS58 encoded address
	if regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{46,48}$`).MatchString(address) {
		// Validate it's a proper Polkadot address format
		if pm.validatePolkadotAddress(address) {
			return Polkadot
		}
	}

	// Cosmos/ATOM address: starts with cosmos, typically followed by 38-45 characters
	if regexp.MustCompile(`^(cosmos|cosmosvaloper)[1-9A-HJ-NP-Za-km-z]{38,45}$`).MatchString(address) {
		// Validate it's a proper Cosmos address format
		if pm.validateCosmosAddress(address) {
			return Cosmos
		}
	}

	return Unknown
}

// validateEthereumAddress performs additional checks on an Ethereum address
func (pm *PatternMatcher) validateEthereumAddress(address string) bool {
	// Basic validation: must start with 0x followed by 40 hex characters
	if !regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`).MatchString(address) {
		return false
	}

	// If address has mixed case, validate the checksum
	// This is a simplified validation
	hasLower := false
	hasUpper := false

	for _, c := range address[2:] { // Skip 0x prefix
		if c >= 'a' && c <= 'f' {
			hasLower = true
		} else if c >= 'A' && c <= 'F' {
			hasUpper = true
		}
	}

	// If address has both uppercase and lowercase letters, it should be a checksum address
	// For simplicity, we'll accept it as valid (a full implementation would verify the checksum)
	if hasLower && hasUpper {
		// In a full implementation, we would verify the checksum here
		return true
	}

	// For all lowercase or all uppercase, just accept as valid
	return true
}

// validateBitcoinAddress performs checks on a Bitcoin address
func (pm *PatternMatcher) validateBitcoinAddress(address string) bool {
	// Basic validation based on prefix and length
	if address[0] == '1' { // P2PKH
		return len(address) >= 26 && len(address) <= 34
	} else if address[0] == '3' { // P2SH
		return len(address) >= 26 && len(address) <= 34
	} else if strings.HasPrefix(address, "bc1") { // Bech32
		// Extra validation for bech32 - should only include certain characters
		valid := true
		for _, c := range address[3:] { // Skip bc1 prefix
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
				valid = false
				break
			}
		}
		return valid && len(address) >= 14 && len(address) <= 74
	}

	return false
}

// validateSolanaAddress performs checks on a Solana address
func (pm *PatternMatcher) validateSolanaAddress(address string) bool {
	// Basic validation: Solana uses ed25519 public keys encoded in base58
	// Check if it's a valid base58 string
	for _, c := range address {
		// Base58 doesn't include: 0, O, I, l
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return false
		}
	}

	// Simple length check - Solana addresses are typically 32-44 chars in base58
	return len(address) >= 32 && len(address) <= 44
}

// validateLitecoinWIF performs checks on a Litecoin WIF private key
func (pm *PatternMatcher) validateLitecoinWIF(key string) bool {
	// Basic validation: the prefix indicates the network
	prefix := key[0]
	switch prefix {
	case '6': // Uncompressed key for mainnet
		return len(key) == 51 || len(key) == 52
	case 'T': // Compressed key for mainnet
		return len(key) == 52
	default:
		return false
	}

	// More robust validation would include base58 decoding and checksum verification
	// Simplified validation for common formats
	//return true
}

// validateLitecoinAddress performs checks on a Litecoin address
func (pm *PatternMatcher) validateLitecoinAddress(address string) bool {
	// Basic validation based on prefix and length
	if address[0] == 'L' { // P2PKH
		return len(address) >= 26 && len(address) <= 34
	} else if address[0] == 'M' { // P2SH
		return len(address) >= 26 && len(address) <= 34
	} else if strings.HasPrefix(address, "ltc1") { // Bech32
		// Extra validation for bech32 - should only include certain characters
		valid := true
		for _, c := range address[4:] { // Skip ltc1 prefix
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
				valid = false
				break
			}
		}
		return valid && len(address) >= 26 && len(address) <= 42
	}

	return false
}

// validateMoneroKey performs checks on a Monero private key
func (pm *PatternMatcher) validateMoneroKey(key string) bool {
	// Basic validation for Monero key format
	// Monero uses either:
	// - 64 hex characters for spend key
	// - 64 hex characters for view key

	// Check if it's a valid hex string
	for _, c := range key {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}

	// Simple length check - Monero private keys are exactly 64 hex characters
	return len(key) == 64
}

// validateMoneroAddress performs checks on a Monero address
func (pm *PatternMatcher) validateMoneroAddress(address string) bool {
	// Basic validation for Monero address
	// Monero addresses start with 4 and are typically 95-106 characters long

	// Check if it starts with 4
	if !strings.HasPrefix(address, "4") {
		return false
	}

	// Check length
	if len(address) < 95 || len(address) > 106 {
		return false
	}

	// Check if it's a valid character set
	for _, c := range address {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}

	return true
}

// detectCryptoTypeFromKeyword identifies the cryptocurrency type from a keyword
func (pm *PatternMatcher) detectCryptoTypeFromKeyword(keyword string) CryptoType {
	keyword = strings.ToLower(keyword)

	switch {
	case strings.Contains(keyword, "bitcoin") || strings.Contains(keyword, "btc"):
		return Bitcoin
	case strings.Contains(keyword, "ethereum") || strings.Contains(keyword, "eth") || strings.Contains(keyword, "metamask"):
		return Ethereum
	case strings.Contains(keyword, "solana") || strings.Contains(keyword, "sol") || strings.Contains(keyword, "solflare") || strings.Contains(keyword, "phantom"):
		return Solana
	case strings.Contains(keyword, "monero") || strings.Contains(keyword, "xmr"):
		return Monero
	case strings.Contains(keyword, "litecoin") || strings.Contains(keyword, "ltc"):
		return Litecoin
	case strings.Contains(keyword, "cardano") || strings.Contains(keyword, "ada"):
		return CryptoType("Cardano")
	case strings.Contains(keyword, "ripple") || strings.Contains(keyword, "xrp"):
		return CryptoType("Ripple")
	case strings.Contains(keyword, "polkadot") || strings.Contains(keyword, "dot"):
		return CryptoType("Polkadot")
	case strings.Contains(keyword, "cosmos") || strings.Contains(keyword, "atom"):
		return CryptoType("Cosmos")
	default:
		return Unknown
	}
}

// validateSeedPhrase checks if a potential seed phrase consists of valid BIP39 words
func (pm *PatternMatcher) validateSeedPhrase(phrase string) bool {
	words := strings.Fields(phrase)

	// Valid seed phrases have 12, 15, 18, 21, or 24 words
	validLengths := map[int]bool{
		12: true,
		15: true,
		18: true,
		21: true,
		24: true,
	}

	// Strict length validation - must be exactly one of the valid lengths
	if !validLengths[len(words)] {
		return false
	}

	// Check if each word is in the BIP39 word list
	validWords := 0
	for _, word := range words {
		if pm.wordList[strings.ToLower(word)] {
			validWords++
		}
	}

	// Stricter validation - at least 90% of words must be valid BIP39 words
	// This catches typos but allows for some variance in real-world files
	return float64(validWords)/float64(len(words)) >= 0.9
}

// deprecated - use validateAndDeriveSeedPhrase from key_validator.go instead

// calculateSeedPhraseProbability determines the likelihood that a match is a valid seed phrase
func (pm *PatternMatcher) calculateSeedPhraseProbability(phrase string) float64 {
	words := strings.Fields(phrase)

	// Valid seed phrases have specific lengths
	validLengths := map[int]bool{
		12: true,
		15: true,
		18: true,
		21: true,
		24: true,
	}

	if !validLengths[len(words)] {
		return 0.05 // Very low probability if wrong length
	}

	// Calculate what percentage of words are in the BIP39 word list
	validWords := 0
	for _, word := range words {
		if pm.wordList[strings.ToLower(word)] {
			validWords++
		}
	}

	// If all words are valid, high confidence
	ratio := float64(validWords) / float64(len(words))
	if ratio == 1.0 {
		return 1.0 // 100% confidence when all words match
	} else if ratio >= 0.95 {
		return 0.95 // High confidence with 95%+ BIP39 words
	} else if ratio >= 0.9 {
		return 0.8 // Good confidence with 90%+ BIP39 words
	} else if ratio >= 0.8 {
		return 0.6 // Moderate confidence with 80%+ BIP39 words
	}

	return ratio * 0.5 // Lower confidence for other matches
}

// getContext returns a substring around the match for context
func getContext(line, match string) string {
	// Find the match position
	idx := strings.Index(strings.ToLower(line), strings.ToLower(match))
	if idx == -1 {
		return line // Fallback
	}

	// Get context (20 chars before and after)
	startIdx := max(0, idx-20)
	endIdx := min(len(line), idx+len(match)+20)

	// Safety check: ensure startIdx is not greater than endIdx
	if startIdx > endIdx {
		return line // If indices are invalid, return the whole line as fallback
	}

	// Add ellipsis if truncated
	prefix := ""
	if startIdx > 0 {
		prefix = "..."
	}

	suffix := ""
	if endIdx < len(line) {
		suffix = "..."
	}

	return prefix + line[startIdx:endIdx] + suffix
}

// abs returns the absolute value of x
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// validatePrivateKeyWithType performs a comprehensive validation on private keys
// and returns detailed validation result including error messages
func validatePrivateKeyWithType(key string, cryptoType CryptoType) (bool, string, string) {
	var validationResult *crypto.KeyValidationResult
	var err error

	switch cryptoType {
	case Ethereum:
		validationResult, err = crypto.ValidateAndDeriveEthereumPrivateKey(key)
	case Bitcoin:
		validationResult, err = crypto.ValidateAndDeriveBitcoinPrivateKey(key)
	case Litecoin:
		validationResult, err = crypto.ValidateAndDeriveLitecoinPrivateKey(key)
	case Solana:
		validationResult, err = crypto.ValidateAndDeriveSolanaPrivateKey(key)
	case Monero:
		validationResult, err = crypto.ValidateAndDeriveMoneroPrivateKey(key)
	case Cardano:
		validationResult, err = crypto.ValidateAndDeriveCardanoPrivateKey(key)
	case Ripple:
		validationResult, err = crypto.ValidateAndDeriveRipplePrivateKey(key)
	case Polkadot:
		validationResult, err = crypto.ValidateAndDerivePolkadotPrivateKey(key)
	case Cosmos:
		validationResult, err = crypto.ValidateAndDeriveCosmosPrivateKey(key)
	default:
		// For types without crypto validation yet, just return true with a derived placeholder address
		return true, derivePlaceholderWallet(key, cryptoType), ""
	}

	if err != nil {
		// If there's an error, we still want to return a placeholder wallet
		generatedPlaceholder := derivePlaceholderWallet(key, cryptoType)
		return false, generatedPlaceholder, err.Error()
	}

	if validationResult == nil || !validationResult.IsValid {
		// Even for invalid keys, generate a placeholder wallet
		generatedPlaceholder := derivePlaceholderWallet(key, cryptoType)
		return false, generatedPlaceholder, "Key validation failed"
	}

	// If we have a valid key but no wallet address was derived, generate a placeholder
	if validationResult.DerivedWallet == "" {
		validationResult.DerivedWallet = derivePlaceholderWallet(key, cryptoType)
	}

	return true, validationResult.DerivedWallet, ""
}

// isValidPrivateKey performs a comprehensive validation on private keys
func isValidPrivateKey(key string, cryptoType CryptoType) (bool, string) {
	valid, derivedWallet, _ := validatePrivateKeyWithType(key, cryptoType)
	return valid, derivedWallet
}

// isValidWalletAddress performs a comprehensive validation on wallet addresses
// by delegating to the crypto package's validation functions
func isValidWalletAddress(address string, cryptoType CryptoType) bool {
	var result *crypto.WalletValidationResult

	switch cryptoType {
	case Ethereum:
		result = crypto.ValidateEthereumAddress(address)
	case Bitcoin:
		result = crypto.ValidateBitcoinAddress(address)
	case Litecoin:
		result = crypto.ValidateLitecoinAddress(address)
	case Monero:
		result = crypto.ValidateMoneroAddress(address)
	case Solana:
		result = crypto.ValidateSolanaAddress(address)
	case Cardano:
		result = crypto.ValidateCardanoAddress(address)
	case Ripple:
		result = crypto.ValidateRippleAddress(address)
	case Polkadot:
		result = crypto.ValidatePolkadotAddress(address)
	case Cosmos:
		result = crypto.ValidateCosmosAddress(address)
	default:
		// For unknown types, fall back to basic validation
		// (this probably should be improved in a real implementation)
		return true
	}

	return result != nil && result.IsValid
}

// validateEthereumKeyComprehensive performs comprehensive validation on Ethereum private keys
func validateEthereumKeyComprehensive(key string) bool {
	// Strip 0x prefix if present
	if strings.HasPrefix(key, "0x") {
		key = key[2:]
	}

	// Basic validation: must be 64 hex characters exactly
	if len(key) != 64 {
		return false
	}

	// Validate that it's a valid hex string
	for _, c := range key {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}

	// A valid Ethereum key must not be all zeros
	nonZero := false
	for _, c := range key {
		if c != '0' {
			nonZero = true
			break
		}
	}

	// The private key must be less than the secp256k1 curve order
	// This is an oversimplification - a real implementation would check against the actual curve order
	// We're just checking it's not obviously invalid
	if strings.HasPrefix(strings.ToLower(key), "ff") &&
		strings.ToLower(key) > "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141" {
		return false
	}

	return nonZero
}

// validateBitcoinWIFComprehensive performs comprehensive validation on Bitcoin WIF keys
func validateBitcoinWIFComprehensive(key string) bool {
	// Bitcoin WIF validationsic validation: the prefix indicates the network and compression
	prefix := key[0]

	// Check if the key contains only valid base58 characters
	for _, c := range key {
		// Base58 doesn't include: 0, O, I, l
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return false
		}
	}

	// Check for valid prefix and length
	switch prefix {
	case '5': // Uncompressed key for mainnet
		return len(key) == 51
	case 'K', 'L': // Compressed key for mainnet
		return len(key) == 52
	default:
		return false
	}

	// Note: A full implementation would validate the checksum by:
	// 1. Decoding the base58 string
	// 2. Extracting the checksum (last 4 bytes)
	// 3. Recalculating the checksum (double SHA256 hash of the first N-4 bytes)
	// 4. Comparing calculated checksum with extracted checksum
}

// validateLitecoinWIFComprehensive performs comprehensive validation on Litecoin WIF keys
func validateLitecoinWIFComprehensive(key string) bool {
	// Basic validation: the prefix indicates the network
	prefix := key[0]

	// Check if the key contains only valid base58 characters
	for _, c := range key {
		// Base58 doesn't include: 0, O, I, l
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return false
		}
	}

	// Check for valid prefix and length
	switch prefix {
	case '6': // Uncompressed key for mainnet
		return len(key) == 51 || len(key) == 52
	case 'T': // Compressed key for mainnet
		return len(key) == 52
	default:
		return false
	}
}

// validateSolanaKeyComprehensive performs comprehensive validation on Solana private keys
func validateSolanaKeyComprehensive(key string) bool {
	// Solana uses ed25519 keypairs which are typically encoded in base58

	// Check if it's a valid base58 string
	for _, c := range key {
		// Base58 doesn't include: 0, O, I, l
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return false
		}
	}

	// Typical length check for Solana private key encoded in base58
	return len(key) >= 87 && len(key) <= 88
}

// validateMoneroKeyComprehensive performs comprehensive validation on Monero private keys
func validateMoneroKeyComprehensive(key string) bool {
	// Monero private keys are exactly 64 hex characters
	if len(key) != 64 {
		return false
	}

	// Validate that it's a valid hex string
	for _, c := range key {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}

	// Monero private keys have additional validation:
	// 1. They must be less than the Ed25519 curve order (2^252 + 27742317777372353535851937790883648493)
	// This is an oversimplification - just check it's not all zeros or beyond the highest byte
	if key == strings.Repeat("0", 64) {
		return false
	}
	if strings.ToLower(key) > "f000000000000000000000000000000000000000000000000000000000000000" {
		return false
	}

	return true
}

// validateEthereumAddressComprehensive performs comprehensive validation on Ethereum addresses
func validateEthereumAddressComprehensive(address string) bool {
	// Basic validation: must start with 0x followed by 40 hex characters
	if !regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`).MatchString(address) {
		return false
	}

	// If address has mixed case, validate the checksum using EIP-55
	hasLower := false
	hasUpper := false

	for _, c := range address[2:] { // Skip 0x prefix
		if c >= 'a' && c <= 'f' {
			hasLower = true
		} else if c >= 'A' && c <= 'F' {
			hasUpper = true
		}
	}

	// If address has both uppercase and lowercase letters, it should follow EIP-55 checksum
	// Here we just validate that it has a proper mixed-case format without implementing the full checksum validation
	// A full implementation would calculate the checksum using keccak256 hash as specified in EIP-55
	if hasLower && hasUpper {
		// For now, just accept it as potentially valid
		// In a real implementation we would calculate the proper checksum
		return true
	}

	// For all lowercase or all uppercase, check if it's a potential contract address
	// Contract addresses typically have non-zero bytes after position 0
	if (address[2] != '0' || address[3] != '0') &&
		!strings.HasPrefix(strings.ToLower(address[2:]), "0000000000000000000000") {
		return true
	}

	// For all zeros, it's definitely not valid
	if strings.ToLower(address) == "0x0000000000000000000000000000000000000000" {
		return false
	}

	// Basic format validation passed
	return true
}

// validateBitcoinAddressComprehensive performs comprehensive validation on Bitcoin addresses
func validateBitcoinAddressComprehensive(address string) bool {
	// P2PKH addresses start with 1
	if address[0] == '1' {
		return len(address) >= 26 && len(address) <= 34 && validateBase58Address(address)
	}

	// P2SH addresses start with 3
	if address[0] == '3' {
		return len(address) >= 26 && len(address) <= 34 && validateBase58Address(address)
	}

	// Bech32 addresses start with bc1
	if strings.HasPrefix(address, "bc1") {
		// Extra validation for bech32 - should only include certain characters
		return validateBech32Address(address, 3) // 3 is the length of the prefix "bc1"
	}

	return false
}

// validateLitecoinAddressComprehensive performs comprehensive validation on Litecoin addresses
func validateLitecoinAddressComprehensive(address string) bool {
	// P2PKH addresses start with L
	if address[0] == 'L' {
		return len(address) >= 26 && len(address) <= 34 && validateBase58Address(address)
	}

	// P2SH addresses start with M
	if address[0] == 'M' {
		return len(address) >= 26 && len(address) <= 34 && validateBase58Address(address)
	}

	// Bech32 addresses start with ltc1
	if strings.HasPrefix(address, "ltc1") {
		// Extra validation for bech32 - should only include certain characters
		return validateBech32Address(address, 4) // 4 is the length of the prefix "ltc1"
	}

	return false
}

// validateSolanaAddressComprehensive performs comprehensive validation on Solana addresses
func validateSolanaAddressComprehensive(address string) bool {
	// Basic validation: Solana uses ed25519 public keys encoded in base58
	// Check if it's a valid base58 string
	for _, c := range address {
		// Base58 doesn't include: 0, O, I, l
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return false
		}
	}

	// Solana public key is always 32 bytes which typically results in 43-44 base58 characters
	// Some special addresses may be shorter
	if len(address) < 32 || len(address) > 44 {
		return false
	}

	// Additional check for well-known invalid addresses
	if address == "11111111111111111111111111111111" {
		return false
	}

	// Basic format validation passed
	return true
}

// validateMoneroAddressComprehensive performs comprehensive validation on Monero addresses
func validateMoneroAddressComprehensive(address string) bool {
	// Monero addresses start with 4 and are typically 95-106 characters long
	if !strings.HasPrefix(address, "4") {
		return false
	}

	// Basic length check
	if len(address) < 95 || len(address) > 106 {
		return false
	}

	// Check character set - Monero addresses only use a specific subset of ASCII
	for _, c := range address {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}

	// Well-known invalid pattern check
	if strings.HasPrefix(address, "44444444444444444444444444444") {
		return false
	}

	// Basic format validation passed
	return true
}

// validateBase58Address validates base58 encoded addresses
func validateBase58Address(address string) bool {
	// Check if the address contains only valid base58 characters
	for _, c := range address {
		// Base58 doesn't include: 0, O, I, l
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return false
		}
		// Base58 only includes these characters
		if !((c >= '1' && c <= '9') || (c >= 'A' && c <= 'H') || (c >= 'J' && c <= 'N') ||
			(c >= 'P' && c <= 'Z') || (c >= 'a' && c <= 'k') || (c >= 'm' && c <= 'z')) {
			return false
		}
	}

	// Note: A full implementation would validate the checksum

	return true
}

// validateBech32Address validates Bech32 encoded addresses
func validateBech32Address(address string, prefixLen int) bool {
	// Bech32 addresses should only contain specific characters
	validBech32 := true
	for _, c := range address[prefixLen:] { // Skip prefix (bc1 or ltc1)
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
			validBech32 = false
			break
		}
	}

	// Check length based on format (segwit v0 vs v1)
	// SegWit v0 addresses are 42 chars for P2WPKH, 62 chars for P2WSH
	// SegWit v1 (Taproot) addresses are longer

	// For bc1 or ltc1 addresses, validate appropriate lengths
	if prefixLen == 3 { // Bitcoin
		// bc1q prefix for v0, bc1p for v1
		if strings.HasPrefix(address, "bc1q") {
			return validBech32 && (len(address) == 42 || len(address) == 62)
		} else if strings.HasPrefix(address, "bc1p") {
			return validBech32 && len(address) == 62
		}
	} else if prefixLen == 4 { // Litecoin
		// ltc1q prefix for v0
		if strings.HasPrefix(address, "ltc1q") {
			return validBech32 && (len(address) == 43 || len(address) == 63)
		}
	}

	// Basic format validation passed if it contains valid characters
	return validBech32
}

// validateCardanoKey performs checks on a Cardano private key
func (pm *PatternMatcher) validateCardanoKey(key string) bool {
	// Cardano keys come in different formats
	// Extended keys (ed25519e_sk or xprv) followed by encoded data

	// Check if it's in extended format
	if strings.HasPrefix(key, "ed25519e_sk") || strings.HasPrefix(key, "ed25519_sk") || strings.HasPrefix(key, "xprv") {
		// For extended keys, check the remaining part for valid encoding (base58/base16)
		var suffix string
		if strings.HasPrefix(key, "xprv") {
			suffix = key[4:]
		} else if strings.HasPrefix(key, "ed25519_sk") {
			suffix = key[10:]
		} else { // ed25519e_sk
			suffix = key[11:]
		}

		// Check for valid base58 characters in the suffix
		for _, c := range suffix {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') ||
				((c >= '1' && c <= '9') || (c >= 'A' && c <= 'H') || (c >= 'J' && c <= 'N') ||
					(c >= 'P' && c <= 'Z') || (c >= 'a' && c <= 'k') || (c >= 'm' && c <= 'z'))) {
				return false
			}
		}
		return true
	}

	// Check for path-based format (addr_sk or stake_sk)
	if strings.HasPrefix(key, "addr_sk") || strings.HasPrefix(key, "stake_sk") {
		// Path-based keys have a specific format that follows the prefix
		var suffix string
		if strings.HasPrefix(key, "addr_sk") {
			suffix = key[7:]
		} else {
			suffix = key[8:]
		}

		// The suffix should be hex encoded
		for _, c := range suffix {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}

		return len(suffix) >= 50
	}

	return false
}

// validateRippleKey performs checks on a Ripple/XRP private key
func (pm *PatternMatcher) validateRippleKey(key string) bool {
	// Ripple private keys typically start with 's' followed by base58 encoded data
	if !strings.HasPrefix(key, "s") {
		return false
	}

	// Ripple secret keys should be 28-29 characters (including 's')
	if len(key) != 29 && len(key) != 28 {
		return false
	}

	// Check if it's a valid base58 string
	for _, c := range key[1:] {
		// Base58 doesn't include: 0, O, I, l
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return false
		}
		// Base58 only includes these characters
		if !((c >= '1' && c <= '9') || (c >= 'A' && c <= 'H') || (c >= 'J' && c <= 'N') ||
			(c >= 'P' && c <= 'Z') || (c >= 'a' && c <= 'k') || (c >= 'm' && c <= 'z')) {
			return false
		}
	}

	return true
}

// validatePolkadotKey performs checks on a Polkadot private key
func (pm *PatternMatcher) validatePolkadotKey(key string) bool {
	// Check for base64-like patterns that are commonly false positives
	if len(key) == 48 && (strings.ContainsRune(key, '/') || strings.ContainsRune(key, '+') || 
		strings.HasSuffix(key, "=") || strings.HasSuffix(key, "==")) {
		return false  // Likely base64 encoded data, not a Polkadot key
	}

	// Check if we can decode it as base64 - if it produces valid printable ASCII, it's likely not a key
	if len(key) >= 40 && len(key) <= 48 {
		// Attempt to see if this is readable text encoded as base64
		// Real Polkadot keys shouldn't decode to readable ASCII
		hasNonPrintableChars := false
		for _, c := range key {
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || 
				c == '+' || c == '/' || c == '=') {
				hasNonPrintableChars = true
				break
			}
		}
		
		// If it contains only base64-compatible chars, it's likely encoded data not a key
		if !hasNonPrintableChars {
			return false
		}
	}

	// Polkadot keys can be in hex format (with or without 0x) or base58 format

	// For keys starting with 'x' (may be a shorthand format seen in some contexts)
	if strings.HasPrefix(key, "x") {
		// The key after 'x' must be valid hex chars AND have a length of exactly 64 chars (standard hex key length)
		hexPart := key[1:]
		if len(hexPart) != 64 {
			return false
		}

		// Check if it's a valid hex string
		for _, c := range hexPart {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
		
		// Check for all zeros (invalid key)
		if strings.ToLower(hexPart) == strings.Repeat("0", 64) {
			return false
		}

		return true
	}

	// If it's hex format
	if strings.HasPrefix(key, "0x") {
		// Check if it's a valid hex string
		for _, c := range key[2:] {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
		
		// Check for all zeros (invalid key)
		if strings.ToLower(key[2:]) == strings.Repeat("0", 64) {
			return false
		}
		
		return len(key) == 66 // 0x + 64 chars
	} else if len(key) == 64 && regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(key) {
		// Hex without 0x prefix
		// Check for all zeros (invalid key)
		if strings.ToLower(key) == strings.Repeat("0", 64) {
			return false
		}
		return true
	} else {
		// Base58 format - must be either 47 or 48 characters exactly
		if len(key) != 47 && len(key) != 48 {
			return false
		}

		// Check if it contains only valid base58 characters
		for _, c := range key {
			if c == '0' || c == 'O' || c == 'I' || c == 'l' {
				return false
			}
			// Base58 only includes these characters
			if !((c >= '1' && c <= '9') || (c >= 'A' && c <= 'H') || (c >= 'J' && c <= 'N') ||
				(c >= 'P' && c <= 'Z') || (c >= 'a' && c <= 'k') || (c >= 'm' && c <= 'z')) {
				return false
			}
		}
		return true
	}
}

// validateCosmosKey performs checks on a Cosmos/ATOM key
func (pm *PatternMatcher) validateCosmosKey(key string) bool {
	// Cosmos keys can be in different formats, but public keys usually start with cosmos or cosmosvaloper
	if strings.HasPrefix(key, "cosmos") || strings.HasPrefix(key, "cosmosvaloper") {
		// Get the part after the prefix
		var suffix string
		if strings.HasPrefix(key, "cosmos") {
			suffix = key[6:]
		} else {
			suffix = key[13:]
		}

		// Check for valid bech32 characters in the suffix
		for _, c := range suffix {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
				return false
			}
		}

		// Length check for Cosmos addresses
		return len(suffix) >= 38 && len(suffix) <= 45
	}

	// Check for hex encoded private key format (64 characters)
	if len(key) == 64 {
		for _, c := range key {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
		return true
	}

	return false
}

// validateCardanoAddress performs checks on a Cardano address
func (pm *PatternMatcher) validateCardanoAddress(address string) bool {
	// Cardano addresses start with specific prefixes: addr1, stake1, etc.

	// Check for valid prefix
	if !strings.HasPrefix(address, "addr1") && !strings.HasPrefix(address, "stake1") {
		return false
	}

	// Check the characters are valid (Bech32 format)
	for _, c := range address[6:] { // Skip prefix (addr1 or stake1)
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}

	// Lengths vary based on the type, but all are relatively long
	return len(address) >= 59 && len(address) <= 120
}

// validateRippleAddress performs checks on a Ripple address
func (pm *PatternMatcher) validateRippleAddress(address string) bool {
	// Basic format checks
	if !strings.HasPrefix(address, "r") {
		return false
	}
	
	// Ripple addresses MUST be 25-35 characters in length
	if len(address) < 25 || len(address) > 35 {
		return false
	}
	
	// Check if it contains only valid base58 characters
	for _, c := range address[1:] {
		// Base58 doesn't include: 0, O, I, l
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return false
		}
		// Base58 only includes specific characters
		if !((c >= '1' && c <= '9') || (c >= 'A' && c <= 'H') || (c >= 'J' && c <= 'N') ||
			(c >= 'P' && c <= 'Z') || (c >= 'a' && c <= 'k') || (c >= 'm' && c <= 'z')) {
			return false
		}
	}
	
	return true
}

// validatePolkadotAddress performs checks on a Polkadot address
func (pm *PatternMatcher) validatePolkadotAddress(address string) bool {
	// Polkadot addresses are SS58 encoded and typically 46-48 characters

	// Check for valid base58 characters
	for _, c := range address {
		// Base58 doesn't include: 0, O, I, l
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return false
		}
		// Base58 only includes specific characters
		if !((c >= '1' && c <= '9') || (c >= 'A' && c <= 'H') || (c >= 'J' && c <= 'N') ||
			(c >= 'P' && c <= 'Z') || (c >= 'a' && c <= 'k') || (c >= 'm' && c <= 'z')) {
			return false
		}
	}

	// Polkadot addresses are usually 46-48 characters long
	return len(address) >= 46 && len(address) <= 48
}

// validateCosmosAddress performs checks on a Cosmos/ATOM address
func (pm *PatternMatcher) validateCosmosAddress(address string) bool {
	// Cosmos addresses start with cosmos or cosmosvaloper prefix
	if !strings.HasPrefix(address, "cosmos") && !strings.HasPrefix(address, "cosmosvaloper") {
		return false
	}

	// Get the part after the prefix
	var suffix string
	if strings.HasPrefix(address, "cosmos") {
		suffix = address[6:]
	} else {
		suffix = address[13:]
	}

	// Check for valid bech32 characters in the suffix
	for _, c := range suffix {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}

	// Cosmos addresses are typically between 39-50 characters long
	return len(address) >= 39 && len(address) <= 50
}

// validateCosmosAddressComprehensive performs comprehensive validation on Cosmos/ATOM addresses
func validateCosmosAddressComprehensive(address string) bool {
	// Cosmos addresses start with cosmos or cosmosvaloper prefix
	if !strings.HasPrefix(address, "cosmos") && !strings.HasPrefix(address, "cosmosvaloper") {
		return false
	}

	// Get the part after the prefix
	var suffix string
	if strings.HasPrefix(address, "cosmos") {
		suffix = address[6:]
	} else {
		suffix = address[13:]
	}

	// Check for valid bech32 characters in the suffix
	for _, c := range suffix {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}

	// Cosmos addresses are typically between 39-50 characters long
	return len(address) >= 39 && len(address) <= 50
}

// validateCardanoKeyComprehensive performs comprehensive validation on Cardano private keys
func validateCardanoKeyComprehensive(key string) bool {
	// Cardano keys come in different formats
	// Extended keys (ed25519e_sk or xprv) followed by encoded data

	// Check if it's in extended format
	if strings.HasPrefix(key, "ed25519e_sk") || strings.HasPrefix(key, "ed25519_sk") || strings.HasPrefix(key, "xprv") {
		// For extended keys, check the remaining part for valid encoding (base58/base16)
		for _, c := range key[strings.Index(key, "_sk")+3:] {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') ||
				((c >= '1' && c <= '9') || (c >= 'A' && c <= 'H') || (c >= 'J' && c <= 'N') ||
					(c >= 'P' && c <= 'Z') || (c >= 'a' && c <= 'k') || (c >= 'm' && c <= 'z'))) {
				return false
			}
		}
		return true
	}

	return false
}

// validateRippleKeyComprehensive performs comprehensive validation on Ripple/XRP private keys
func validateRippleKeyComprehensive(key string) bool {
	// Ripple private keys typically start with 's' followed by base58 encoded data
	if !strings.HasPrefix(key, "s") {
		return false
	}

	// Ripple secret keys should be exactly 29 characters (including 's')
	if len(key) != 29 {
		return false
	}

	// Check if it's a valid base58 string
	for _, c := range key[1:] {
		// Base58 doesn't include: 0, O, I, l
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return false
		}
		// Base58 only includes these characters
		if !((c >= '1' && c <= '9') || (c >= 'A' && c <= 'H') || (c >= 'J' && c <= 'N') ||
			(c >= 'P' && c <= 'Z') || (c >= 'a' && c <= 'k') || (c >= 'm' && c <= 'z')) {
			return false
		}
	}

	return true
}

// validatePolkadotKeyComprehensive performs comprehensive validation on Polkadot private keys
func validatePolkadotKeyComprehensive(key string) bool {
	// Polkadot keys can be in hex format (with or without 0x) or base58 format

	// For keys starting with 'x' (may be a shorthand format)
	if strings.HasPrefix(key, "x") {
		// The key after 'x' must be valid hex chars AND have a length of exactly 64 chars
		hexPart := key[1:]
		if len(hexPart) != 64 {
			return false
		}
		// Check if it's a valid hex string
		for _, c := range hexPart {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
		return true
	}

	// If it's hex format
	if strings.HasPrefix(key, "0x") {
		// Check if it's a valid hex string
		for _, c := range key[2:] {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
		return len(key) == 66 // 0x + 64 chars
	} else if len(key) == 64 && regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(key) {
		// Hex without 0x prefix
		return true
	} else {
		// Base58 format - must be either 47 or 48 characters exactly
		if len(key) != 47 && len(key) != 48 {
			return false
		}

		// Check if it contains only valid base58 characters
		for _, c := range key {
			if c == '0' || c == 'O' || c == 'I' || c == 'l' {
				return false
			}
			// Base58 only includes these characters
			if !((c >= '1' && c <= '9') || (c >= 'A' && c <= 'H') || (c >= 'J' && c <= 'N') ||
				(c >= 'P' && c <= 'Z') || (c >= 'a' && c <= 'k') || (c >= 'm' && c <= 'z')) {
				return false
			}
		}
		return true
	}
}

// validateCardanoAddressComprehensive performs comprehensive validation on Cardano addresses
func validateCardanoAddressComprehensive(address string) bool {
	// Cardano addresses start with specific prefixes: addr1, stake1, etc.

	// Check for valid prefix
	if !strings.HasPrefix(address, "addr1") && !strings.HasPrefix(address, "stake1") {
		return false
	}

	// Check the characters are valid (Bech32 format)
	for _, c := range address[6:] { // Skip prefix (addr1 or stake1)
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}

	// Lengths vary based on the type, but all are relatively long
	return len(address) >= 59 && len(address) <= 120
}

// validateRippleAddressComprehensive performs comprehensive validation on Ripple/XRP addresses
func validateRippleAddressComprehensive(address string) bool {
	// Ripple addresses start with r and use base58 encoding
	if !strings.HasPrefix(address, "r") {
		return false
	}

	// Check if it's a valid base58 string
	for _, c := range address[1:] {
		// Base58 doesn't include: 0, O, I, l
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return false
		}
		// Base58 only includes specific characters
		if !((c >= '1' && c <= '9') || (c >= 'A' && c <= 'H') || (c >= 'J' && c <= 'N') ||
			(c >= 'P' && c <= 'Z') || (c >= 'a' && c <= 'k') || (c >= 'm' && c <= 'z')) {
			return false
		}
	}

	// Ripple addresses are typically 25-35 characters in length
	return len(address) >= 25 && len(address) <= 35
}

// validateCosmosKeyComprehensive performs comprehensive validation on Cosmos keys
func validateCosmosKeyComprehensive(key string) bool {
	// Cosmos keys can be in different formats, but public keys usually start with cosmos or cosmosvaloper
	if strings.HasPrefix(key, "cosmos") || strings.HasPrefix(key, "cosmosvaloper") {
		// Check for valid base58 characters in the rest of the string
		for _, c := range key[len("cosmos"):] {
			// Base58 doesn't include: 0, O, I, l
			if c == '0' || c == 'O' || c == 'I' || c == 'l' {
				return false
			}
		}
		// Length check for Cosmos addresses
		return len(key) >= 39 && len(key) <= 50
	}

	return false
}

// validatePolkadotAddressComprehensive performs comprehensive validation on Polkadot addresses
func validatePolkadotAddressComprehensive(address string) bool {
	// Polkadot addresses are SS58 encoded and typically 46-48 characters

	// Check for valid base58 characters
	for _, c := range address {
		// Base58 doesn't include: 0, O, I, l
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return false
		}
		// Base58 only includes specific characters
		if !((c >= '1' && c <= '9') || (c >= 'A' && c <= 'H') || (c >= 'J' && c <= 'N') ||
			(c >= 'P' && c <= 'Z') || (c >= 'a' && c <= 'k') || (c >= 'm' && c <= 'z')) {
			return false
		}
	}

	// Polkadot addresses are usually 46-48 characters long
	return len(address) >= 46 && len(address) <= 48
}
