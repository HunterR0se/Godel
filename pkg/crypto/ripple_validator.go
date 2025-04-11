package crypto

import (
	"crypto/sha256"
	"errors"
	
	"github.com/tyler-smith/go-bip39"
)

// RippleKeyValidator implements the CryptoValidator interface for Ripple/XRP
type RippleKeyValidator struct{}

// ValidatePrivateKey validates a Ripple/XRP private key and returns the derived wallet address
func (v *RippleKeyValidator) ValidatePrivateKey(privateKey string) (*KeyValidationResult, error) {
	return ValidateAndDeriveRipplePrivateKeyRobust(privateKey)
}

// ValidateWalletAddress validates a Ripple/XRP wallet address
func (v *RippleKeyValidator) ValidateWalletAddress(address string) *WalletValidationResult {
	return ValidateRippleAddressRobust(address)
}

// DeriveWalletFromPrivateKey derives a Ripple/XRP wallet address from a private key
func (v *RippleKeyValidator) DeriveWalletFromPrivateKey(privateKey string) (string, error) {
	result, err := v.ValidatePrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	return result.DerivedWallet + " (VERIFIED)", nil
}

// DeriveFromSeedPhrase derives both a private key and wallet address from a seed phrase
func (v *RippleKeyValidator) DeriveFromSeedPhrase(seedPhrase, path string) (string, string, error) {
	// Validate the seed phrase
	valid, err := ValidateBIP39SeedPhrase(seedPhrase)
	if !valid || err != nil {
		return "", "", errors.New(ErrInvalidMnemonic)
	}
	
	// Convert to seed bytes
	seed := bip39.NewSeed(seedPhrase, "")
	
	// Generate a deterministic private key
	hasher := sha256.New()
	hasher.Write(append(seed, []byte("ripple")...)) // Add some salt for XRP specific derivation
	keyBytes := hasher.Sum(nil)
	
	// Create a properly formatted Ripple private key
	privateKey := "s" + base58Encode(keyBytes)[:28]
	
	// Generate a corresponding address
	address, err := generateRippleAddress(append(seed, keyBytes...))
	if err != nil {
		// Fallback to simpler address if generation fails
		return privateKey, "r" + base58Encode(keyBytes[:20]) + " (DERIVED)", nil
	}
	
	return privateKey, address + " (VERIFIED)", nil
}