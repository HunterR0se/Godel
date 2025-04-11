package crypto

// ValidateAndDeriveBitcoinPrivateKey validates a Bitcoin private key and derives its wallet address
func ValidateAndDeriveBitcoinPrivateKey(key string) (*KeyValidationResult, error) {
	validator := &BitcoinKeyValidator{}
	return validator.ValidatePrivateKey(key)
}