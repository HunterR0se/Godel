package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/grendel/godel/internal/cli"
	"github.com/grendel/godel/internal/scanner"
	"github.com/grendel/godel/pkg/ui"
)

func main() {
	// Define command line flags
	dirPath := flag.String("dir", ".", "The directory path to scan")
	recursive := flag.Bool("r", true, "Scan directories recursively")
	threads := flag.Int("threads", runtime.NumCPU(), "Number of worker threads")
	verbose := flag.Bool("v", false, "Show verbose output including non-matches")
	maxSize := flag.Int64("maxsize", 1024, "Maximum file size in MB to process (default: 1024MB/1GB)")
	help := flag.Bool("help", false, "Display help information")

	// Parse the flags
	flag.Parse()

	// Initialize color scheme for consistent formatting
	cs := ui.DefaultColorScheme()

	// Check if no arguments or help flag is provided
	if len(os.Args) == 1 || *help {
		cli.DisplayHelp(cs)
		return
	}

	// Print application header
	ui.PrintHeader(cs, "Gödel - The Incompletely Recursive Crypto Explorer")

	// Display scanning information
	cs.Result.Print("Scanning directory: ")
	cs.Path.Println(*dirPath)
	cs.Normal.Printf("Using %d worker threads\n", *threads)

	// Print command example to filter results by crypto type
	cs.Normal.Println("Hint: Use the -v flag to see all potential matches")
	cs.Normal.Printf("      Filter output using grep: %s | grep -A 5 'Type: Bitcoin'\n", os.Args[0])

	// Run the scan
	result, err := scanner.ScanDirectory(*dirPath, *recursive, *threads, *maxSize, *verbose)
	if err != nil {
		log.Fatalf("Scan error: %v", err)
	}

	// Print summary footer
	if result.ValidMatches > 0 {
		message := fmt.Sprintf("Analysis complete! Found %d unique matches", result.ValidMatches)
		if *verbose {
			message += fmt.Sprintf(" and filtered out %d duplicates/low-quality matches", result.IgnoredMatches)

			// Report failed validation counts in verbose mode
			var failedKeysTotal int
			for _, count := range result.FailedKeysByType {
				if count > 0 {
					failedKeysTotal += count
				}
			}

			if failedKeysTotal > 0 {
				message += fmt.Sprintf("\nDetected %d invalid keys that didn't pass validation", failedKeysTotal)

				// Show the detailed breakdown in a separate message to avoid truncation
				ui.PrintFooter(cs, message)

				// Add detailed breakdown by crypto type
				cs.Result.Println("Error breakdown by cryptocurrency type:")
				for cryptoType, count := range result.FailedKeysByType {
					if count > 0 {
						cs.Error.Printf("  - %s: %d failed keys\n", cryptoType, count)
					}
				}
				fmt.Println()
				return
			}
		}
		ui.PrintFooter(cs, message)
	} else {
		ui.PrintFooter(cs, "Analysis complete! No matches found")
	}
}