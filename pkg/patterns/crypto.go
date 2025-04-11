package patterns

import "regexp"

// CryptoKeyPatterns provides regular expressions for common cryptocurrency private key formats
type CryptoKeyPatterns struct {
	// Ethereum private key (64 hex characters)
	Ethereum *regexp.Regexp

	// Bitcoin WIF private key (starts with 5, K, or L followed by base58 characters)
	BitcoinWIF *regexp.Regexp

	// Solana private key (base58 or base64 format)
	Solana *regexp.Regexp
	
	// Cardano private key (typically a mnemonic phrase)
	Cardano *regexp.Regexp
	
	// Ripple private key 
	Ripple *regexp.Regexp
	
	// Polkadot private key
	Polkadot *regexp.Regexp
	
	// Cosmos private key
	Cosmos *regexp.Regexp

	// Generic hex private key (64 hex characters)
	GenericHex *regexp.Regexp
}

// GetCryptoKeyPatterns returns compiled regular expressions for crypto key formats
func GetCryptoKeyPatterns() *CryptoKeyPatterns {
	return &CryptoKeyPatterns{
		// Ethereum private key: 64 hex characters (without 0x prefix)
		Ethereum: regexp.MustCompile(`(?i)(0x)?[0-9a-f]{64}`),

		// Bitcoin WIF private key: starts with 5, K, or L followed by base58 chars (about 51 chars total)
		BitcoinWIF: regexp.MustCompile(`(?i)[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$`),

		// Solana private key: in base58 or base64 format
		Solana: regexp.MustCompile(`(?i)[1-9A-HJ-NP-Za-km-z]{87,88}|[A-Za-z0-9+/]{87,88}={0,2}`),
		
		// Cardano private key: extended key format with prefixes
		Cardano: regexp.MustCompile(`(?i)(ed25519e?_sk|xprv)[1-9A-HJ-NP-Za-km-z]{96,107}`),
		
		// Ripple private key: typical 's' prefix for secret keys
		Ripple: regexp.MustCompile(`(?i)s[1-9A-HJ-NP-Za-km-z]{28,29}$`),
		
		// Polkadot private key: SS58 format or hex format with x prefix
		Polkadot: regexp.MustCompile(`(?i)x[0-9a-f]{64}|[1-9A-HJ-NP-Za-km-z]{47,48}$`),
		
		// Cosmos private key: 64-character hex format or bech32 format
		Cosmos: regexp.MustCompile(`(?i)(cosmosvaloper|cosmos)[1-9A-HJ-NP-Za-km-z]{38,45}|[0-9a-f]{64}`),

		// Generic hex private key: 64 hex characters that could be any blockchain
		GenericHex: regexp.MustCompile(`(?i)[0-9a-f]{64}`),
	}
}

// GetWalletKeywords returns common wallet-related keywords to search for
func GetWalletKeywords() []string {
	return []string{
		// General wallet terms
		"wallet", "private key", "secret key", "seed phrase", "recovery phrase", 
		"mnemonic", "passphrase", "backup phrase", "seed words",

		// Cryptocurrency terms
		"bitcoin", "btc", "ethereum", "eth", "solana", "sol", "binance", "bnb",
		"tether", "usdt", "ripple", "xrp", "cardano", "ada", "dogecoin", "doge",
		"polkadot", "dot", "uniswap", "uni", "litecoin", "ltc", "monero", "xmr",
		"cosmos", "atom", "terra", "luna", "avalanche", "avax",

		// Wallet software/services
		"metamask", "solflare", "exodus", "trust wallet", "ledger", "trezor",
		"coinbase", "binance wallet", "blockchain.com", "phantom", "myetherwallet",
		"electrum", "jaxx", "atomic wallet", "safepal", "crypto.com", "cake wallet",
		
		// Cardano wallets
		"yoroi", "daedalus", "eternl", "nami wallet", "flint", "typhon", "adalite",
		
		// Ripple/XRP wallets
		"xumm wallet", "toast wallet", "gatehub", "bithomp", "xrptoolkit",
		
		// Polkadot wallets
		"polkadot.js", "polkawallet", "nova wallet", "subwallet", "fearless wallet",
		"talisman", "enzyme", "mathwallet", "polkadot{.js}", "parity signer",
		
		// Cosmos wallets
		"keplr", "cosmostation", "leap cosmos", "lunie", "trust cosmos", "wetez", "rainbow",
		"frontier cosmos", "starname", "nansen", "chainapsis",
	}
}