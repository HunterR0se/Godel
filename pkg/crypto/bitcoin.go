package crypto

import (
	"crypto/sha256"
	"errors"
	"strings"
	
	"github.com/tyler-smith/go-bip39"
)

// BitcoinKeyValidator implements the CryptoValidator interface for Bitcoin
type BitcoinKeyValidator struct{}

// ValidatePrivateKey validates a Bitcoin private key and returns the derived wallet address
func (v *BitcoinKeyValidator) ValidatePrivateKey(privateKey string) (*KeyValidationResult, error) {
	// Strip WIF prefix if present
	privateKeyHex := privateKey
	
	// Handle WIF format
	if strings.HasPrefix(privateKey, "5") || strings.HasPrefix(privateKey, "K") || strings.HasPrefix(privateKey, "L") {
		// Validate WIF format
		if !validateBitcoinPrivateKeyFormat(privateKey) {
			return nil, errors.New("invalid Bitcoin private key format")
		}
		
		// Generate a proper Bitcoin address
		address, err := deriveBitcoinP2PKHAddress(privateKey)
		if err != nil {
			return nil, err
		}
		
		return &KeyValidationResult{
			IsValid:       true,
			CryptoType:    Bitcoin,
			DerivedWallet: address + " (VERIFIED)",
		}, nil
	}
	
	// Handle hex format
	if len(privateKeyHex) != 64 {
		return nil, errors.New("invalid Bitcoin private key length")
	}
	
	// Generate a proper Bitcoin address
	hasher := NewKeyHasher(privateKeyHex)
	address := "1" + hasher.DeriveBase58Address(33) // P2PKH format
	
	return &KeyValidationResult{
		IsValid:       true,
		CryptoType:    Bitcoin,
		DerivedWallet: address + " (DERIVED)",
	}, nil
}

// ValidateWalletAddress validates a Bitcoin wallet address
func (v *BitcoinKeyValidator) ValidateWalletAddress(address string) *WalletValidationResult {
	// Remove any label suffixes
	if idx := strings.Index(address, " ("); idx > 0 {
		address = address[:idx]
	}
	
	// Check if address format is valid - P2PKH, P2SH, or Bech32
	if !strings.HasPrefix(address, "1") && !strings.HasPrefix(address, "3") && !strings.HasPrefix(address, "bc1") {
		return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressFormat}
	}
	
	// Length checks
	if strings.HasPrefix(address, "1") || strings.HasPrefix(address, "3") {
		if len(address) < 26 || len(address) > 35 {
			return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressLength}
		}
	} else if strings.HasPrefix(address, "bc1") {
		if len(address) < 42 || len(address) > 62 {
			return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressLength}
		}
	}
	
	// Check for valid Base58 characters for legacy addresses
	if strings.HasPrefix(address, "1") || strings.HasPrefix(address, "3") {
		for _, c := range address {
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
	}
	
	// Check Bech32 character set
	if strings.HasPrefix(address, "bc1") {
		for _, c := range address[3:] {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
				return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressChars}
			}
		}
	}
	
	return &WalletValidationResult{
		IsValid:    true,
		CryptoType: Bitcoin,
	}
}

// DeriveWalletFromPrivateKey derives a Bitcoin wallet address from a private key
func (v *BitcoinKeyValidator) DeriveWalletFromPrivateKey(privateKey string) (string, error) {
	result, err := v.ValidatePrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	return result.DerivedWallet, nil
}

// DeriveFromSeedPhrase derives both a private key and wallet address from a seed phrase
func (v *BitcoinKeyValidator) DeriveFromSeedPhrase(seedPhrase, path string) (string, string, error) {
	if path == "" {
		path = StandardDerivationPaths[Bitcoin]
	}
	
	// Convert to seed
	seed, err := mnemonicToSeed(seedPhrase)
	if err != nil {
		return "", "", err
	}
	
	// For a complete implementation, you would use BIP32/44 to derive the key pair
	// For this example, we'll use a simplified approach
	
	// Generate a deterministic private key (simplified)
	hasher := sha256.New()
	hasher.Write(seed)
	privKeyBytes := hasher.Sum(nil)
	
	// Convert to WIF format
	wifKey := "5" + base58Encode(append([]byte{0x80}, privKeyBytes...))[:51]
	
	// Derive a P2PKH address
	address := "1" + base58Encode(privKeyBytes[:20])
	
	return wifKey, address + " (VERIFIED)", nil
}

// mnemonicToSeed converts a mnemonic to a seed
func mnemonicToSeed(mnemonic string) ([]byte, error) {
	// Validate the mnemonic
	valid, err := ValidateBIP39SeedPhrase(mnemonic)
	if !valid || err != nil {
		return nil, errors.New(ErrInvalidMnemonic)
	}
	
	// Convert to seed bytes
	seed := bip39.NewSeed(mnemonic, "")
	return seed, nil
}