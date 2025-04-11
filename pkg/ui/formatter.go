package ui

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

const (
	// BoxWidth is the standard width for display boxes
	BoxWidth = 80
)

// ColorScheme defines a set of colors for consistent UI formatting
type ColorScheme struct {
	Header   *color.Color // For box borders and section headers
	Title    *color.Color // For main titles
	Subtitle *color.Color // For section titles
	Normal   *color.Color // For normal text
	Param    *color.Color // For parameter names
	Path     *color.Color // For file paths
	File     *color.Color // For filenames
	Match    *color.Color // For match indicators
	Type     *color.Color // For type indicators
	Result   *color.Color // For result messages
	Key      *color.Color // For key information
	Example  *color.Color // For example commands
	Success  *color.Color // For success messages (high confidence)
	Error    *color.Color // For error messages (low confidence)
}

// DefaultColorScheme returns the default color scheme for the application
func DefaultColorScheme() *ColorScheme {
	return &ColorScheme{
		Header:   color.New(color.FgBlue, color.Bold),
		Title:    color.New(color.FgHiWhite, color.Bold),
		Subtitle: color.New(color.FgBlue),
		Normal:   color.New(color.FgWhite),
		Param:    color.New(color.FgCyan),
		Path:     color.New(color.FgCyan),
		File:     color.New(color.FgGreen),
		Match:    color.New(color.FgYellow),
		Type:     color.New(color.FgHiWhite, color.Bold),
		Result:   color.New(color.FgBlue),
		Key:      color.New(color.FgHiCyan),
		Example:  color.New(color.FgGreen),
		Success:  color.New(color.FgGreen, color.Bold),
		Error:    color.New(color.FgRed),
	}
}

// PrintHeader prints a formatted header box with the given title
func PrintHeader(cs *ColorScheme, title string) {
	padding := BoxWidth - 4 - len(title) // 5 is for "│  " and " │"

	fmt.Println()
	cs.Header.Println("╭─────────────────────────────────────────────────────────────────────────────╮")
	cs.Header.Printf("│  ")
	cs.Title.Print(title)
	cs.Header.Printf("%s│\n", strings.Repeat(" ", padding))
	cs.Header.Println("╰─────────────────────────────────────────────────────────────────────────────╯")
	fmt.Println()
}

// PrintFooter prints a formatted footer box with the given message
func PrintFooter(cs *ColorScheme, message string) {
	// If message is too long, truncate it
	if len(message) > BoxWidth - 6 {  // Allow 6 chars for "│  " and " │"
		message = message[:BoxWidth-9] + "..."
	}
	
	padding := BoxWidth - 4 - len(message) // 4 is for "│  " and " │"
	if padding < 0 {
		padding = 0
	}

	fmt.Println()
	cs.Header.Println("╭──────────────────────────────────────────────────────────────────────────────╮")
	cs.Header.Printf("│  ")
	cs.Result.Print(message)
	cs.Header.Printf("%s│\n", strings.Repeat(" ", padding))
	cs.Header.Println("╰──────────────────────────────────────────────────────────────────────────────╯")
	fmt.Println()
}

// PrintOption prints a command line option with description
func PrintOption(cs *ColorScheme, flag, description string) {
	cs.Normal.Print("  ")
	cs.Param.Print(flag)
	cs.Normal.Println(description)
}

// PrintExample prints a usage example
func PrintExample(cs *ColorScheme, example, description string) {
	cs.Example.Printf("  %s", example)
	if description != "" {
		cs.Example.Printf("  # %s", description)
	}
	fmt.Println()
}

// PrintSectionHeader prints a section header
func PrintSectionHeader(cs *ColorScheme, title string) {
	cs.Subtitle.Println(title)
}

// PrintMatchHeader prints a header for a match result
func PrintMatchHeader(cs *ColorScheme, number int, matchType string, isValidMatch bool) {
	if !isValidMatch {
		cs.Match.Printf("  (Not a match) #%d: ", number)
	} else {
		cs.Match.Printf("Match #%d: ", number)
	}
	cs.Type.Printf("%s\n", matchType)
}
