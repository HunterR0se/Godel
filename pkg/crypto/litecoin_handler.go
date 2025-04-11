package crypto

// ValidateAndDeriveLitecoinPrivateKey validates a Litecoin private key and derives its wallet address
func ValidateAndDeriveLitecoinPrivateKey(key string) (*KeyValidationResult, error) {
	// For now, use the validateLitecoinPrivateKey function
	return validateLitecoinPrivateKey(key)
}