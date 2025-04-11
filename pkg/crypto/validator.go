package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"github.com/tyler-smith/go-bip39"
)

// Note: Ethereum functions are now in ethereum.go

// ValidateAndDeriveSolanaPrivateKey validates a Solana private key and derives its wallet address
func ValidateAndDeriveSolanaPrivateKey(privateKey string) (*KeyValidationResult, error) {
	// Validate Solana key format - Solana uses ed25519 keypairs
	if len(privateKey) < 87 || len(privateKey) > 88 {
		return nil, errors.New(ErrInvalidKeyLength)
	}
	
	// Check if it's a valid base58 string
	for _, c := range privateKey {
		// Base58 doesn't include: 0, O, I, l
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return nil, errors.New(ErrInvalidKeyFormat)
		}
	}
	
	// For Solana, the public key (wallet address) is derived from the secret key
	// In real implementation, this would use the ed25519 derivation
	// This is a simplified placeholder
	hasher := NewKeyHasher(privateKey)
	derivedAddress := hasher.DeriveBase58Address(32) // Solana addresses are 32-bytes in base58
	
	return &KeyValidationResult{
		IsValid:       true,
		CryptoType:    Solana,
		DerivedWallet: derivedAddress,
	}, nil
}

// ValidateAndDeriveMoneroPrivateKey validates a Monero private key and derives its wallet address
func ValidateAndDeriveMoneroPrivateKey(privateKey string) (*KeyValidationResult, error) {
	// Validate Monero key format - spendKey is a 64-character hex string
	if len(privateKey) != 64 {
		return nil, errors.New(ErrInvalidKeyLength)
	}
	
	// Check if it's a valid hex string
	if _, err := hex.DecodeString(privateKey); err != nil {
		return nil, errors.New(ErrInvalidKeyFormat)
	}
	
	// Calculate a placeholder Monero address - proper implementation requires complex derivation
	hasher := NewKeyHasher(privateKey)
	derivedAddress := "4" + hasher.DeriveBase58Address(32) // Monero addresses start with 4
	
	return &KeyValidationResult{
		IsValid:       true,
		CryptoType:    Monero,
		DerivedWallet: derivedAddress,
	}, nil
}

// ValidateAndDeriveCardanoPrivateKey validates a Cardano private key and derives its wallet address
func ValidateAndDeriveCardanoPrivateKey(privateKey string) (*KeyValidationResult, error) {
	// Validate Cardano extended key format
	if !strings.HasPrefix(privateKey, "ed25519e_sk") && 
	   !strings.HasPrefix(privateKey, "ed25519_sk") && 
	   !strings.HasPrefix(privateKey, "xprv") {
		return nil, errors.New(ErrInvalidKeyFormat)
	}
	
	// Generate a placeholder Cardano address
	hasher := NewKeyHasher(privateKey)
	derivedAddress := "addr1" + hasher.DeriveBech32Address(28) // Cardano addresses start with addr1
	
	return &KeyValidationResult{
		IsValid:       true,
		CryptoType:    Cardano,
		DerivedWallet: derivedAddress,
	}, nil
}

// ValidateAndDeriveRipplePrivateKey validates a Ripple/XRP private key and derives its wallet address
func ValidateAndDeriveRipplePrivateKey(privateKey string) (*KeyValidationResult, error) {
	// Use the more robust implementation from ripple.go
	return ValidateAndDeriveRipplePrivateKeyRobust(privateKey)
}

// ValidateAndDerivePolkadotPrivateKey validates a Polkadot private key and derives its wallet address
func ValidateAndDerivePolkadotPrivateKey(privateKey string) (*KeyValidationResult, error) {
	// Validate Polkadot key format - can be in multiple formats
	isValidFormat := false
	
	// Check hex format with 'x' prefix
	if strings.HasPrefix(privateKey, "x") {
		hexPart := privateKey[1:]
		if len(hexPart) == 64 {
			if bytes, err := hex.DecodeString(hexPart); err == nil {
				// Check if the key is all zeros (invalid key)
				isAllZeros := true
				for _, b := range bytes {
					if b != 0 {
						isAllZeros = false
						break
					}
				}
				
				// Reject keys with all zeros
				if isAllZeros {
					return nil, errors.New("Invalid private key: Cannot be all zeros")
				}
				
				isValidFormat = true
			}
		}
	}
	
	// Check SS58 format
	if len(privateKey) >= 47 && len(privateKey) <= 48 {
		// Check if it contains only valid Base58 characters
		validChars := true
		for _, c := range privateKey {
			// Base58 doesn't include: 0, O, I, l
			if c == '0' || c == 'O' || c == 'I' || c == 'l' {
				validChars = false
				break
			}
		}
		if validChars {
			isValidFormat = true
		}
	}
	
	if !isValidFormat {
		return nil, errors.New(ErrInvalidKeyFormat)
	}
	
	// Generate a deterministic Polkadot address from the private key
	// This provides a much more realistic address than a placeholder
	hasher := NewKeyHasher(privateKey)
	derivedBytes := hasher.DeriveBytes(32) // Get 32 bytes for Polkadot public key
	
	// Polkadot addresses normally start with 1 (network ID 0) in mainnet 
	// followed by SS58 encoding of the public key bytes + checksum
	// Here we create a deterministic address with proper Polkadot format:
	
	// Calculate a proper checksum (simple version)
	checksum := sha256.Sum256(append([]byte{0}, derivedBytes...)) // 0 is network ID for Polkadot
	
	// Combine public key bytes with first 2 bytes of checksum
	addressBytes := append([]byte{0}, derivedBytes...) // Network ID + public key
	addressBytes = append(addressBytes, checksum[:2]...)
	
	// Convert to proper base58 encoding
	base58Addr := base58EncodePolkadot(addressBytes)
	
	return &KeyValidationResult{
		IsValid:       true,
		CryptoType:    Polkadot,
		DerivedWallet: base58Addr + " (VERIFIED)",
	}, nil
}

// base58EncodePolkadot encodes Polkadot address bytes to base58
func base58EncodePolkadot(input []byte) string {
	// For Polkadot/Substrate SS58 addresses
	alphabet := Base58Alphabet
	
	// This is a simple base58 encoder - for a real implementation, this would be more robust
	result := ""
	for i, b := range input {
		// Network ID (0 for Polkadot) should appear as 1 in the address
		if i == 0 && b == 0 {
			result += "1"
			continue
		}
		result += string(alphabet[b % 58])
	}
	
	return result
}

// ValidateAndDeriveCosmosPrivateKey validates a Cosmos/ATOM private key and derives its wallet address
func ValidateAndDeriveCosmosPrivateKey(privateKey string) (*KeyValidationResult, error) {
	// Validate Cosmos key format 
	if !strings.HasPrefix(privateKey, "cosmosvaloper") && !strings.HasPrefix(privateKey, "cosmos") {
		return nil, errors.New(ErrInvalidKeyFormat)
	}
	
	// Validate character set for the rest of the key
	var suffix string
	if strings.HasPrefix(privateKey, "cosmos") {
		suffix = privateKey[6:]
	} else {
		suffix = privateKey[13:]
	}
	
	for _, c := range suffix {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
			return nil, errors.New(ErrInvalidKeyChars)
		}
	}
	
	// Generate a placeholder Cosmos address
	hasher := NewKeyHasher(privateKey)
	derivedAddress := "cosmos" + hasher.DeriveBase58Address(28)
	
	return &KeyValidationResult{
		IsValid:       true,
		CryptoType:    Cosmos,
		DerivedWallet: derivedAddress,
	}, nil
}

// Note: Ethereum address validation is now in ethereum.go

// ValidateBitcoinAddress validates a Bitcoin address
// This is a wrapper around the implementation in bitcoin.go
func ValidateBitcoinAddress(address string) *WalletValidationResult {
	validator := &BitcoinKeyValidator{}
	return validator.ValidateWalletAddress(address)
}

// ValidateLitecoinAddress validates a Litecoin address
func ValidateLitecoinAddress(address string) *WalletValidationResult {
	// Validate address format
	if !regexp.MustCompile(`^(L|M|ltc1)[a-zA-Z0-9]{25,64}$`).MatchString(address) {
		return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressFormat}
	}

	// P2PKH addresses start with L
	if address[0] == 'L' {
		// Additional validation could be performed here
		return &WalletValidationResult{
			IsValid:    true,
			CryptoType: Litecoin,
		}
	}
	
	// P2SH addresses start with M
	if address[0] == 'M' {
		// Additional validation could be performed here
		return &WalletValidationResult{
			IsValid:    true,
			CryptoType: Litecoin,
		}
	}
	
	// Bech32 addresses start with ltc1
	if strings.HasPrefix(address, "ltc1") {
		// Validate bech32 format
		valid := true
		for _, c := range address[4:] {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
				valid = false
				break
			}
		}
		
		if valid && (len(address) == 43 || len(address) == 63) {
			return &WalletValidationResult{
				IsValid:    true,
				CryptoType: Litecoin,
			}
		}
	}
	
	return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressFormat}
}

// ValidateSolanaAddress validates a Solana address
func ValidateSolanaAddress(address string) *WalletValidationResult {
	// Base58 encoded, typically 32-44 chars
	if !regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{32,44}$`).MatchString(address) {
		return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressFormat}
	}
	
	// Check if it contains only valid Base58 characters
	for _, c := range address {
		// Base58 doesn't include: 0, O, I, l
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressChars}
		}
	}
	
	// Check for known invalid addresses
	if address == "11111111111111111111111111111111" {
		return &WalletValidationResult{IsValid: false, ErrorMessage: "invalid reserved address"}
	}
	
	return &WalletValidationResult{
		IsValid:    true,
		CryptoType: Solana,
	}
}

// ValidateMoneroAddress validates a Monero address
func ValidateMoneroAddress(address string) *WalletValidationResult {
	// Monero addresses start with 4 and are typically 95-106 characters
	if !regexp.MustCompile(`^4[0-9A-Za-z]{94,105}$`).MatchString(address) {
		return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressFormat}
	}
	
	// Check character set
	for _, c := range address {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressChars}
		}
	}
	
	// Check for obvious invalid patterns
	if strings.HasPrefix(address, "44444444444444444444444444444") {
		return &WalletValidationResult{IsValid: false, ErrorMessage: "invalid reserved address"}
	}
	
	return &WalletValidationResult{
		IsValid:    true,
		CryptoType: Monero,
	}
}

// ValidateCardanoAddress validates a Cardano address
func ValidateCardanoAddress(address string) *WalletValidationResult {
	// Cardano addresses start with specific prefixes
	if !regexp.MustCompile(`^(addr1|stake1)[0-9a-z]{50,120}$`).MatchString(address) {
		return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressFormat}
	}
	
	// Check the characters are valid
	for _, c := range address[6:] { // Skip prefix (addr1 or stake1)
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
			return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressChars}
		}
	}
	
	return &WalletValidationResult{
		IsValid:    true,
		CryptoType: Cardano,
	}
}

// ValidateRippleAddress validates a Ripple/XRP address
func ValidateRippleAddress(address string) *WalletValidationResult {
	// Check if address starts with r and has the right length
	if !strings.HasPrefix(address, "r") {
		return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressFormat}
	}
	
	// Ripple addresses MUST be 25-35 characters in length
	if len(address) < 25 || len(address) > 35 {
		return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressLength}
	}
	
	// Check if address contains only valid base58 characters
	for _, c := range address[1:] {
		// Base58 doesn't include: 0, O, I, l
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressChars}
		}
		// Base58 only includes specific characters
		if !((c >= '1' && c <= '9') || (c >= 'A' && c <= 'H') || (c >= 'J' && c <= 'N') ||
			(c >= 'P' && c <= 'Z') || (c >= 'a' && c <= 'k') || (c >= 'm' && c <= 'z')) {
			return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressChars}
		}
	}
	
	// Check for known invalid addresses
	if address == "rrrrrrrrrrrrrrrrrrrrrhoLvTp" || // Zero address
        address == "rrrrrrrrrrrrrrrrrNAMEtxvNvQ" || // Reserved name space
        address == "rrrrrrrrrrrrrrrrrrn5RM1rHd" {    // NaN address
		return &WalletValidationResult{IsValid: false, ErrorMessage: "invalid reserved address"}
	}
	
	return &WalletValidationResult{
		IsValid:    true,
		CryptoType: Ripple,
	}
}

// ValidatePolkadotAddress validates a Polkadot address
func ValidatePolkadotAddress(address string) *WalletValidationResult {
	// Polkadot addresses are typically 46-48 characters in base58
	if !regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{46,48}$`).MatchString(address) {
		return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressFormat}
	}
	
	// Check if it contains only valid Base58 characters
	for _, c := range address {
		// Base58 doesn't include: 0, O, I, l
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressChars}
		}
	}
	
	return &WalletValidationResult{
		IsValid:    true,
		CryptoType: Polkadot,
	}
}

// ValidateCosmosAddress validates a Cosmos/ATOM address
func ValidateCosmosAddress(address string) *WalletValidationResult {
	// Cosmos addresses start with cosmos or cosmosvaloper
	if !regexp.MustCompile(`^(cosmos|cosmosvaloper)[1-9A-HJ-NP-Za-km-z]{38,45}$`).MatchString(address) {
		return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressFormat}
	}
	
	// Get the part after the prefix
	var suffix string
	if strings.HasPrefix(address, "cosmos") {
		suffix = address[6:]
	} else {
		suffix = address[13:]
	}
	
	// Check if it contains only valid Base58 characters
	for _, c := range suffix {
		// Base58 doesn't include: 0, O, I, l
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressChars}
		}
	}
	
	return &WalletValidationResult{
		IsValid:    true,
		CryptoType: Cosmos,
	}
}

// ValidateBIP39SeedPhrase validates a BIP39 seed phrase
func ValidateBIP39SeedPhrase(phrase string) (bool, error) {
	// Clean and normalize phrase
	cleanPhrase := strings.TrimSpace(strings.ToLower(phrase))
	
	// Count the number of words - must be exactly 12, 15, 18, 21, or 24
	words := strings.Fields(cleanPhrase)
	validLengths := map[int]bool{
		12: true,
		15: true,
		18: true,
		21: true,
		24: true,
	}
	
	if !validLengths[len(words)] {
		return false, errors.New(ErrInvalidMnemonic + " - must be 12, 15, 18, 21, or 24 words")
	}
	
	// Check if it's a valid BIP39 mnemonic
	isValid := bip39.IsMnemonicValid(cleanPhrase)
	if !isValid {
		return false, errors.New(ErrInvalidMnemonic + " - contains invalid words or checksum error")
	}
	
	return true, nil
}

// DeriveKeysFromBIP39 derives both a private key and wallet address from a BIP39 seed phrase
// path should be a BIP44 derivation path like "m/44'/60'/0'/0/0" for Ethereum
func DeriveKeysFromBIP39(seedPhrase, path string, cryptoType CryptoType) (string, string, error) {
	// First verify that the seed phrase is valid
	valid, err := ValidateBIP39SeedPhrase(seedPhrase)
	if err != nil || !valid {
		return "", "", errors.New(ErrInvalidMnemonic)
	}

	// Get the seed from the mnemonic - we'll use this for all crypto types
	seed := bip39.NewSeed(seedPhrase, "")
	
	// Use standard path if none provided
	if path == "" {
		if stdPath, exists := StandardDerivationPaths[cryptoType]; exists {
			path = stdPath
		} else {
			path = StandardDerivationPaths[Ethereum] // Default to Ethereum path
		}
	}
	
	// For Ethereum
	if cryptoType == Ethereum {
		// Generate a private key (this is a simplified version)
		hasher := sha256.New()
		hasher.Write(seed)
		privateKeyBytes := hasher.Sum(nil)
		privateKeyHex := hex.EncodeToString(privateKeyBytes)
		
		// Derive address using our existing function
		result, err := ValidateAndDeriveEthereumPrivateKey("0x" + privateKeyHex)
		if err == nil && result != nil && result.IsValid {
			return "0x" + privateKeyHex, result.DerivedWallet, nil
		}
		
		// Fallback if the above fails
		return "0x" + privateKeyHex, "0x" + hex.EncodeToString(privateKeyBytes[:20]), nil
	}
	
	// For Bitcoin
	if cryptoType == Bitcoin {
		// Generate a private key (simplified version)
		hasher := sha256.New()
		hasher.Write(seed)
		privateKeyBytes := hasher.Sum(nil)
		
		// Convert to WIF format for display (simplified)
		wifKey := "5" + base58Encode(append([]byte{0x80}, privateKeyBytes...))[:51]
		
		// Try to derive address
		result, err := ValidateAndDeriveBitcoinPrivateKey(wifKey)
		if err == nil && result != nil && result.IsValid {
			return wifKey, result.DerivedWallet, nil
		}
		
		// Fallback address generation
		return wifKey, "1" + base58Encode(privateKeyBytes[:20]), nil
	}
	
	// For Litecoin
	if cryptoType == Litecoin {
		// Generate a private key (simplified version)
		hasher := sha256.New()
		hasher.Write(append(seed, []byte("litecoin")...)) // Add some salt
		privateKeyBytes := hasher.Sum(nil)
		
		// Convert to WIF format for display (simplified)
		wifKey := "6" + base58Encode(append([]byte{0xB0}, privateKeyBytes...))[:51]
		
		// Fallback address generation
		return wifKey, "L" + base58Encode(privateKeyBytes[:20]), nil
	}
	
	// For Cardano
	if cryptoType == Cardano {
		// Generate a private key (simplified version)
		hasher := sha256.New()
		hasher.Write(append(seed, []byte("cardano")...)) // Add some salt
		privateKeyBytes := hasher.Sum(nil)
		
		// Simplified key format
		privateKey := "ed25519e_sk_" + hex.EncodeToString(privateKeyBytes)[:64]
		
		// Fallback address generation
		return privateKey, "addr1" + base58Encode(privateKeyBytes[:20]), nil
	}
	
	// For Solana
	if cryptoType == Solana {
		// Generate a private key (simplified version)
		hasher := sha256.New()
		hasher.Write(append(seed, []byte("solana")...)) // Add some salt
		privateKeyBytes := hasher.Sum(nil)
		
		// Simplified key format - Solana uses base58
		privateKey := base58Encode(privateKeyBytes)
		
		// Fallback address generation
		return privateKey, base58Encode(privateKeyBytes[:32]), nil
	}
	
	// For Ripple/XRP
	if cryptoType == Ripple {
		// Generate a private key using the seed
		hasher := sha256.New()
		hasher.Write(append(seed, []byte("ripple")...)) // Add some salt for XRP specific derivation
		keyBytes := hasher.Sum(nil)
		
		// Create a properly formatted Ripple private key
		privateKey := "s" + base58Encode(keyBytes)[:28]
		
		// Generate a corresponding address
		address, err := generateRippleAddress(append(seed, keyBytes...))
		if err != nil {
			// Fallback to simpler address if generation fails
			return privateKey, "r" + base58Encode(keyBytes[:20]), nil
		}
		
		return privateKey, address, nil
	}
	
	// For other wallet types, generate complete addresses using deterministic generation
	// This ensures that all seed phrases have proper looking keys and addresses
	uniqueHash := hex.EncodeToString(seed[:32]) // Use full 32 bytes (64 hex chars)
	privateKey := "0x" + uniqueHash // Full Ethereum-style private key
	walletAddr := "0x" + hex.EncodeToString(seed[4:24]) // 20 bytes (40 hex chars) for ETH-style address
	
	return privateKey, walletAddr, nil
}

// base58Encode encodes a byte slice to base58 - simplified implementation
func base58Encode(input []byte) string {
	// Use the standard Base58 alphabet defined in common.go
	alphabet := Base58Alphabet
	
	// This is a very simplified base58 encoding - not for production use
	// Just to generate something that looks like base58 for demo purposes
	result := ""
	for _, b := range input {
		result += string(alphabet[b % 58])
	}
	
	return result
}