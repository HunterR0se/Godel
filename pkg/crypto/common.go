package crypto

// common.go - Contains common definitions used across the crypto package
// This file defines constants, types, and interfaces to reduce code duplication

// CryptoType represents a cryptocurrency type
type CryptoType string

// Supported cryptocurrency types
const (
	Unknown  CryptoType = "Unknown"
	Ethereum CryptoType = "Ethereum"
	Bitcoin  CryptoType = "Bitcoin"
	Solana   CryptoType = "Solana"
	Monero   CryptoType = "Monero"
	Litecoin CryptoType = "Litecoin"
	Cardano  CryptoType = "Cardano"
	Ripple   CryptoType = "Ripple"
	Polkadot CryptoType = "Polkadot"
	Cosmos   CryptoType = "Cosmos"
)

// KeyValidationResult represents the result of key validation
type KeyValidationResult struct {
	IsValid       bool      // Whether the key is valid
	CryptoType    CryptoType // Type of cryptocurrency (Ethereum, Bitcoin, etc.)
	DerivedWallet string    // Wallet address derived from the key
	ErrorMessage  string    // Error message if validation failed
}

// WalletValidationResult represents the result of wallet address validation
type WalletValidationResult struct {
	IsValid    bool      // Whether the wallet address is valid
	CryptoType CryptoType // Type of cryptocurrency (Ethereum, Bitcoin, etc.)
	ErrorMessage string   // Error message if validation failed
}

// Base58Alphabet defines the standard Base58 alphabet used by most cryptocurrencies
const Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Common validation error messages
const (
	ErrInvalidKeyLength      = "invalid key length"
	ErrInvalidKeyFormat      = "invalid key format"
	ErrInvalidKeyChars       = "invalid key characters"
	ErrInvalidChecksum       = "invalid checksum"
	ErrInvalidAddressFormat  = "invalid address format"
	ErrInvalidAddressPrefix  = "invalid address prefix"
	ErrInvalidAddressLength  = "invalid address length"
	ErrInvalidAddressChars   = "invalid address characters"
	ErrInvalidMnemonic       = "invalid mnemonic phrase"
	ErrInvalidDerivationPath = "invalid derivation path"
)

// BIP44CoinTypes defines the coin types used in BIP-44 derivation paths
var BIP44CoinTypes = map[CryptoType]uint32{
	Bitcoin:  0,
	Ethereum: 60,
	Litecoin: 2,
	Ripple:   144,
	Solana:   501,
	Polkadot: 354,
	Cosmos:   118,
	Cardano:  1815,
	Monero:   128,
}

// StandardDerivationPaths defines the standard derivation paths for each cryptocurrency
var StandardDerivationPaths = map[CryptoType]string{
	Bitcoin:  "m/44'/0'/0'/0/0",
	Ethereum: "m/44'/60'/0'/0/0",
	Litecoin: "m/44'/2'/0'/0/0",
	Ripple:   "m/44'/144'/0'/0/0",
	Solana:   "m/44'/501'/0'/0/0",
	Polkadot: "m/44'/354'/0'/0/0",
	Cosmos:   "m/44'/118'/0'/0/0",
	Cardano:  "m/1852'/1815'/0'/0/0",
	Monero:   "m/44'/128'/0'/0/0",
}

// GetCryptoValidator returns a validator for a specific cryptocurrency type
func GetCryptoValidator(cryptoType CryptoType) CryptoValidator {
	// TODO: Implement specific validators for each cryptocurrency type
	// For now, return nil
	return nil
}