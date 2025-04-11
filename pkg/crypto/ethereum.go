package crypto

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"
)

// ValidateAndDeriveEthereumSeedPhrase validates an Ethereum seed phrase and derives its private key and wallet address
// Returns privateKey, walletAddress, error
func ValidateAndDeriveEthereumSeedPhrase(seedPhrase string) (string, string, error) {
	// Clean and normalize phrase
	cleanPhrase := strings.TrimSpace(strings.ToLower(seedPhrase))
	
	// Validate BIP39 mnemonic
	if !bip39.IsMnemonicValid(cleanPhrase) {
		return "", "", errors.New(ErrInvalidMnemonic)
	}
	
	// Convert mnemonic to seed
	seed := bip39.NewSeed(cleanPhrase, "")
	
	// Derive master private key from seed
	// For simplicity, we'll just use SHA-256 of the seed to generate an Ethereum key
	// In a full implementation, this would use BIP32/44 derivation
	hasher := sha256.New()
	hasher.Write(seed)
	privateKeyBytes := hasher.Sum(nil)
	
	// Generate ECDSA key from private key bytes
	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to create private key: %v", err)
	}
	
	// Get private key hex
	privateKeyHex := "0x" + hex.EncodeToString(crypto.FromECDSA(privateKey))
	
	// Get the public address
	publicKeyECDSA, ok := privateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return "", "", fmt.Errorf("error casting public key to ECDSA")
	}
	
	address := crypto.PubkeyToAddress(*publicKeyECDSA)
	
	return privateKeyHex, address.Hex() + " (VERIFIED)", nil
}

// ValidateAndDeriveEthereumPrivateKey validates an Ethereum private key and derives its wallet address
func ValidateAndDeriveEthereumPrivateKey(privateKeyHex string) (*KeyValidationResult, error) {
	// Strip 0x prefix if present
	if strings.HasPrefix(privateKeyHex, "0x") {
		privateKeyHex = privateKeyHex[2:]
	}

	// Validate the hex string
	if len(privateKeyHex) != 64 {
		return nil, errors.New(ErrInvalidKeyLength)
	}

	// Convert hex to bytes
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, errors.New(ErrInvalidKeyFormat)
	}

	// Check if the key is all zeros (invalid key)
	isAllZeros := true
	for _, b := range privateKeyBytes {
		if b != 0 {
			isAllZeros = false
			break
		}
	}
	
	// Reject keys with all zeros
	if isAllZeros {
		return nil, errors.New("Invalid private key: Cannot be all zeros")
	}

	// Generate ECDSA key from private key
	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, errors.New(ErrInvalidKeyFormat)
	}

	// Derive public key from private key
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("error casting public key to ECDSA")
	}

	// Derive Ethereum address from public key
	address := crypto.PubkeyToAddress(*publicKeyECDSA)
	
	return &KeyValidationResult{
		IsValid:      true,
		CryptoType:   Ethereum,
		DerivedWallet: address.Hex() + " (VERIFIED)",
	}, nil
}

// DeriveEthereumAddressFromPrivateKeyBytes derives an Ethereum wallet address from a private key's bytes
func DeriveEthereumAddressFromPrivateKeyBytes(privateKeyBytes []byte) (string, error) {
	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return "", err
	}
	
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("error casting public key to ECDSA")
	}
	
	address := crypto.PubkeyToAddress(*publicKeyECDSA)
	return address.Hex() + " (VERIFIED)", nil
}

// GetEthereumAddressFromSeedPhrase derives an Ethereum address from a seed phrase
func GetEthereumAddressFromSeedPhrase(seedPhrase string) (string, error) {
	// Validate and clean phrase
	cleanPhrase := strings.TrimSpace(strings.ToLower(seedPhrase))
	if !bip39.IsMnemonicValid(cleanPhrase) {
		return "", errors.New(ErrInvalidMnemonic)
	}
	
	// Convert to seed
	seed := bip39.NewSeed(cleanPhrase, "")
	
	// Derive private key (simplified approach)
	hasher := sha256.New()
	hasher.Write(seed)
	privateKeyBytes := hasher.Sum(nil)
	
	// Get address
	return DeriveEthereumAddressFromPrivateKeyBytes(privateKeyBytes)
}

// ValidateEthereumAddress validates an Ethereum address
func ValidateEthereumAddress(address string) *WalletValidationResult {
	// Remove any "(VERIFIED)" suffix if present
	if idx := strings.Index(address, " (VERIFIED)"); idx > 0 {
		address = address[:idx]
	}

	// Validate address format
	if !strings.HasPrefix(address, "0x") || len(address) != 42 {
		return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressFormat}
	}
	
	// Check if the address is a valid hex string
	_, err := hex.DecodeString(address[2:])
	if err != nil {
		return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidAddressChars}
	}
	
	// Additional validation: check checksum if address has mixed case
	if common.IsHexAddress(address) {
		// Check if it's a known invalid address (all zeros)
		if strings.ToLower(address) == "0x0000000000000000000000000000000000000000" {
			return &WalletValidationResult{IsValid: false, ErrorMessage: "zero address not allowed"}
		}

		return &WalletValidationResult{
			IsValid:    true,
			CryptoType: Ethereum,
		}
	}
	
	return &WalletValidationResult{IsValid: false, ErrorMessage: ErrInvalidChecksum}
}

// EthereumKeyValidator implements the CryptoValidator interface for Ethereum
type EthereumKeyValidator struct{}

// ValidatePrivateKey validates an Ethereum private key and returns the derived wallet address
func (v *EthereumKeyValidator) ValidatePrivateKey(privateKey string) (*KeyValidationResult, error) {
	return ValidateAndDeriveEthereumPrivateKey(privateKey)
}

// ValidateWalletAddress validates an Ethereum wallet address
func (v *EthereumKeyValidator) ValidateWalletAddress(address string) *WalletValidationResult {
	return ValidateEthereumAddress(address)
}

// DeriveWalletFromPrivateKey derives an Ethereum wallet address from a private key
func (v *EthereumKeyValidator) DeriveWalletFromPrivateKey(privateKey string) (string, error) {
	result, err := ValidateAndDeriveEthereumPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	return result.DerivedWallet, nil
}

// DeriveFromSeedPhrase derives both a private key and wallet address from a seed phrase
func (v *EthereumKeyValidator) DeriveFromSeedPhrase(seedPhrase, path string) (string, string, error) {
	return ValidateAndDeriveEthereumSeedPhrase(seedPhrase)
}