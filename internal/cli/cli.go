package cli

import (
	"fmt"
	"runtime"

	"github.com/grendel/godel/pkg/ui"
)

// DisplayHelp shows usage information for the application
func DisplayHelp(cs *ui.ColorScheme) {
	ui.PrintHeader(cs, "Gödel - The Incompletely Recursive Crypto Explorer")

	ui.PrintSectionHeader(cs, "USAGE:")
	cs.Normal.Println("  godel [options]")
	fmt.Println()

	ui.PrintSectionHeader(cs, "OPTIONS:")
	ui.PrintOption(cs, "-dir     ", "Directory path to scan (default: current directory)")
	ui.PrintOption(cs, "-r       ", "Scan recursively (default: true)")
	ui.PrintOption(cs, "-threads ", fmt.Sprintf("Number of workers (default: %d, the number of CPU cores)", runtime.NumCPU()))
	ui.PrintOption(cs, "-maxsize ", "Maximum file size in MB to process (default: 1024MB/1GB)")
	ui.PrintOption(cs, "-v       ", "Show verbose output including non-matches")
	ui.PrintOption(cs, "-help    ", "Display help information")
	fmt.Println()

	ui.PrintSectionHeader(cs, "EXAMPLES:")
	ui.PrintExample(cs, "godel -dir path           ", "Scan a specific directory")
	ui.PrintExample(cs, "godel -dir scan -r=false  ", "Scan without recursion")
	ui.PrintExample(cs, "godel -dir path -threads=8", "Scan using 8 worker threads")
	ui.PrintExample(cs, "godel -dir path -maxsize=2048", "Set maximum file size to 2GB")
	ui.PrintExample(cs, "godel -dir path -v        ", "Show verbose output including non-matches")
	fmt.Println()

	// Description section
	ui.PrintSectionHeader(cs, "DESCRIPTION:")
	cs.Normal.Println("")
	cs.Normal.Println("  Gödel scans files for potential cryptocurrency wallet information:")
	cs.Normal.Println("")
	cs.Normal.Println("  • BIP39 seed phrases (12, 15, 18, 21, or 24 words)")
	cs.Normal.Println("  • Private keys for various cryptocurrencies")
	cs.Normal.Println("  • Wallet-related keywords with contextual analysis")
	fmt.Println()
	cs.Normal.Println("  When wallet keywords are found, Gödel will show any nearby seed phrases")
	cs.Normal.Println("  or private keys that might be associated with those keywords.")
	cs.Normal.Println("")
}