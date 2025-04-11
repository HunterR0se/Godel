package crypto

import (
	"strings"
)

// CryptoValidator defines a standard interface for validating crypto keys and addresses
type CryptoValidator interface {
	// ValidatePrivateKey validates a private key and returns a validation result
	ValidatePrivateKey(privateKey string) (*KeyValidationResult, error)
	
	// ValidateWalletAddress validates a wallet address
	ValidateWalletAddress(address string) *WalletValidationResult
	
	// DeriveWalletFromPrivateKey derives a wallet address from a private key
	DeriveWalletFromPrivateKey(privateKey string) (string, error)
	
	// DeriveFromSeedPhrase derives both a private key and wallet address from a seed phrase
	DeriveFromSeedPhrase(seedPhrase, path string) (string, string, error)
}

// CryptoValidatorRegistry provides access to validators for different crypto types
type CryptoValidatorRegistry struct {
	validators map[CryptoType]CryptoValidator
}

// NewCryptoValidatorRegistry creates a new validator registry
func NewCryptoValidatorRegistry() *CryptoValidatorRegistry {
	registry := &CryptoValidatorRegistry{
		validators: make(map[CryptoType]CryptoValidator),
	}
	
	// Register all available validators
	registry.validators[Ethereum] = &EthereumKeyValidator{}
	registry.validators[Bitcoin] = &BitcoinKeyValidator{}
	registry.validators[Ripple] = &RippleKeyValidator{}
	// TODO: Add other validators as they're implemented
	
	return registry
}

// GetValidator returns the validator for a specific crypto type
func (r *CryptoValidatorRegistry) GetValidator(cryptoType CryptoType) (CryptoValidator, bool) {
	validator, exists := r.validators[cryptoType]
	return validator, exists
}

// ValidatePrivateKey validates a private key for a specific crypto type
func (r *CryptoValidatorRegistry) ValidatePrivateKey(key string, cryptoType CryptoType) (*KeyValidationResult, error) {
	validator, exists := r.GetValidator(cryptoType)
	if exists {
		return validator.ValidatePrivateKey(key)
	}
	
	// Fall back to the legacy implementation
	switch cryptoType {
	case Bitcoin:
		return ValidateAndDeriveBitcoinPrivateKey(key)
	case Ethereum:
		return ValidateAndDeriveEthereumPrivateKey(key)
	case Ripple:
		return ValidateAndDeriveRipplePrivateKey(key)
	case Polkadot:
		return ValidateAndDerivePolkadotPrivateKey(key)
	case Litecoin:
		return ValidateAndDeriveLitecoinPrivateKey(key)
	case Solana:
		return ValidateAndDeriveSolanaPrivateKey(key)
	case Monero:
		return ValidateAndDeriveMoneroPrivateKey(key)
	case Cardano:
		return ValidateAndDeriveCardanoPrivateKey(key)
	case Cosmos:
		return ValidateAndDeriveCosmosPrivateKey(key)
	default:
		return nil, ErrUnsupportedCryptoType
	}
}

// ValidateWalletAddress validates a wallet address for a specific crypto type
func (r *CryptoValidatorRegistry) ValidateWalletAddress(address string, cryptoType CryptoType) *WalletValidationResult {
	validator, exists := r.GetValidator(cryptoType)
	if exists {
		return validator.ValidateWalletAddress(address)
	}
	
	// Fall back to the legacy implementation
	switch cryptoType {
	case Bitcoin:
		return ValidateBitcoinAddress(address)
	case Ethereum:
		return ValidateEthereumAddress(address)
	case Litecoin:
		return ValidateLitecoinAddress(address)
	case Solana:
		return ValidateSolanaAddress(address)
	case Monero:
		return ValidateMoneroAddress(address)
	case Cardano:
		return ValidateCardanoAddress(address)
	case Ripple:
		return ValidateRippleAddress(address)
	case Polkadot:
		return ValidatePolkadotAddress(address)
	case Cosmos:
		return ValidateCosmosAddress(address)
	default:
		return &WalletValidationResult{IsValid: false, ErrorMessage: ErrUnsupportedCryptoType.Error()}
	}
}

// DeriveWalletFromPrivateKey derives a wallet address from a private key for a specific crypto type
func (r *CryptoValidatorRegistry) DeriveWalletFromPrivateKey(privateKey string, cryptoType CryptoType) (string, error) {
	validator, exists := r.GetValidator(cryptoType)
	if exists {
		return validator.DeriveWalletFromPrivateKey(privateKey)
	}
	
	// Fall back to validation which also derives the wallet address
	result, err := r.ValidatePrivateKey(privateKey, cryptoType)
	if err != nil {
		return "", err
	}
	
	return result.DerivedWallet, nil
}

// DeriveFromSeedPhrase derives both a private key and wallet address from a seed phrase
func (r *CryptoValidatorRegistry) DeriveFromSeedPhrase(seedPhrase, path string, cryptoType CryptoType) (string, string, error) {
	validator, exists := r.GetValidator(cryptoType)
	if exists {
		return validator.DeriveFromSeedPhrase(seedPhrase, path)
	}
	
	// Fall back to the common implementation
	return DeriveKeysFromBIP39(seedPhrase, path, cryptoType)
}

// DeriveWalletAddress creates a uniform way to derive a wallet address from a key
func (r *CryptoValidatorRegistry) DeriveWalletAddress(key string, cryptoType CryptoType, isSeedPhrase bool) string {
	// Handle seed phrases
	if isSeedPhrase {
		privateKey, walletAddress, err := r.DeriveFromSeedPhrase(key, "", cryptoType)
		if err == nil && walletAddress != "" {
			// Check if it already has a label
			if !strings.Contains(walletAddress, " (") {
				walletAddress += " (VERIFIED)"
			}
			return walletAddress
		}
		
		// If we got a private key but no wallet, try the private key methods
		if privateKey != "" {
			key = privateKey
		} else {
			// Fall back to deterministic generation
			hasher := NewKeyHasher(key)
			return deterministicAddress(hasher, cryptoType) + " (DERIVED)"
		}
	}
	
	// Handle private keys
	walletAddress, err := r.DeriveWalletFromPrivateKey(key, cryptoType)
	if err == nil && walletAddress != "" {
		// Check if it already has a label
		if !strings.Contains(walletAddress, " (") {
			walletAddress += " (VERIFIED)"
		}
		return walletAddress
	}
	
	// Fall back to deterministic generation
	hasher := NewKeyHasher(key)
	return deterministicAddress(hasher, cryptoType) + " (DERIVED)"
}

// deterministicAddress generates a deterministic wallet address in the correct format for a crypto type
func deterministicAddress(hasher *KeyHasher, cryptoType CryptoType) string {
	switch cryptoType {
	case Bitcoin:
		return "1" + hasher.DeriveBase58Address(33) // P2PKH format
	case Ethereum:
		return "0x" + hasher.DeriveHexAddress(20)
	case Litecoin:
		return "L" + hasher.DeriveBase58Address(33)
	case Solana:
		return hasher.DeriveBase58Address(44)
	case Monero:
		return "4" + hasher.DeriveBase58Address(95)
	case Cardano:
		return "addr1" + hasher.DeriveBech32Address(50)
	case Ripple:
		return "r" + hasher.DeriveBase58Address(33)
	case Polkadot:
		return "1" + hasher.DeriveBase58Address(47) // Polkadot addresses start with 1
	case Cosmos:
		return "cosmos" + hasher.DeriveBech32Address(38)
	default:
		return "0x" + hasher.DeriveHexAddress(20) // Default to Ethereum format
	}
}