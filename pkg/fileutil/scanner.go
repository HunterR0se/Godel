package fileutil

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// Supported file extensions
var supportedExts = map[string]bool{
	".txt":  true,
	".md":   true,
	".doc":  true,
	".docx": true,
	".rtf":  true,
	".xls":  true,
	".xlsx": true,
	".csv":  true,
	".json": true,
	".xml":  true,
	".html": true,
	".htm":  true,
	".log":  true,
	".cfg":  true,
	".conf": true,
	".ini":  true,
	".pdf":  true, // PDF might require special handling
	".wat":  true,
}

// Scanner represents a file scanner
type Scanner struct {
	isRecursive     bool
	numWorkers      int
	maxFileSize     int64      // Maximum file size in bytes to process
	skipHiddenFiles bool       // Skip hidden files and directories (starting with .)
	excludePaths    []string   // Paths to exclude from scanning
	excludePatterns []string   // Patterns to exclude (using path.Match)
	progressChan    chan int   // Optional progress channel for tracking
}

// NewScanner creates a new Scanner instance with default settings
func NewScanner(isRecursive bool) *Scanner {
	return &Scanner{
		isRecursive:     isRecursive,
		numWorkers:      runtime.NumCPU(), // Default to number of CPU cores
		maxFileSize:     5 * 1024 * 1024 * 1024, // 5GB max file size
		skipHiddenFiles: true,
	}
}

// NewScannerWithConfig creates a new Scanner with custom configuration
func NewScannerWithConfig(isRecursive bool, numWorkers int, maxFileSize int64) *Scanner {
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}
	return &Scanner{
		isRecursive:     isRecursive,
		numWorkers:      numWorkers,
		maxFileSize:     maxFileSize,
		skipHiddenFiles: true,
	}
}

// SetProgressChannel sets a channel for reporting progress
func (s *Scanner) SetProgressChannel(progressChan chan int) {
	s.progressChan = progressChan
}

// SetExcludePatterns sets patterns to exclude from scanning
func (s *Scanner) SetExcludePatterns(patterns []string) {
	s.excludePatterns = patterns
}

// SetExcludePaths sets specific paths to exclude from scanning
func (s *Scanner) SetExcludePaths(paths []string) {
	s.excludePaths = paths
}

// SetSkipHiddenFiles configures whether to skip hidden files and directories
func (s *Scanner) SetSkipHiddenFiles(skip bool) {
	s.skipHiddenFiles = skip
}

// isPathExcluded checks if a path should be excluded based on configured rules
func (s *Scanner) isPathExcluded(path string) bool {
	// Check if path is in the exclude list
	for _, excludePath := range s.excludePaths {
		if path == excludePath || strings.HasPrefix(path, excludePath+"/") {
			return true
		}
	}
	
	// Check if path matches any exclude pattern
	for _, pattern := range s.excludePatterns {
		matched, _ := filepath.Match(pattern, filepath.Base(path))
		if matched {
			return true
		}
	}
	
	// Check if it's a hidden file or directory
	if s.skipHiddenFiles {
		baseName := filepath.Base(path)
		if strings.HasPrefix(baseName, ".") {
			return true
		}
	}
	
	return false
}

// ScanDirectory scans a directory for files with supported extensions
// Returns a list of file paths that match the criteria
func (s *Scanner) ScanDirectory(dirPath string) ([]string, error) {
	// First, collect all eligible files
	var allPaths []string
	var fileCount int

	walkFunc := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Log the error but continue with other files
			fmt.Printf("Warning: Error accessing %s: %v\n", path, err)
			return nil
		}

		// Check if path should be excluded
		if s.isPathExcluded(path) {
			if info.IsDir() && path != dirPath {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip directories unless recursive
		if info.IsDir() {
			if path != dirPath && !s.isRecursive {
				return filepath.SkipDir
			}
			return nil
		}

		// Check file size limit
		if info.Size() > s.maxFileSize {
			fmt.Printf("Skipping file larger than size limit: %s (%d bytes)\n", path, info.Size())
			return nil
		}

		// Check if the file extension is supported
		ext := strings.ToLower(filepath.Ext(path))
		if supportedExts[ext] {
			allPaths = append(allPaths, path)
			fileCount++
			
			// Report progress periodically
			if s.progressChan != nil && fileCount%100 == 0 {
				s.progressChan <- fileCount
			}
		}

		return nil
	}

	err := filepath.Walk(dirPath, walkFunc)
	if err != nil {
		return nil, fmt.Errorf("error walking directory: %v", err)
	}

	// No files found, return empty result
	if len(allPaths) == 0 {
		return []string{}, nil
	}

	// For small numbers of files, don't bother with concurrency
	if len(allPaths) < 10 || s.numWorkers <= 1 {
		return allPaths, nil
	}

	// Now process the files concurrently to filter and validate
	return s.processFilesConcurrently(allPaths)
}

// processFilesConcurrently processes files using multiple goroutines
func (s *Scanner) processFilesConcurrently(paths []string) ([]string, error) {
	var (
		validFiles    = make([]string, 0, len(paths))
		mu            sync.Mutex
		wg            sync.WaitGroup
		numWorkers    = s.numWorkers
		filesChan     = make(chan string, 100) // Buffered channel to reduce contention
		errorsChan    = make(chan error, numWorkers)
		fileProcessed = 0
	)

	// If there are fewer files than workers, adjust the number of workers
	if len(paths) < numWorkers {
		numWorkers = len(paths)
	}

	// Context could be used here for cancellation if needed in the future

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for path := range filesChan {
				// Try to validate the file without fully reading it
				isValid, err := s.validateFile(path)
				if err != nil {
					// Log error but continue with other files
					fmt.Printf("Worker %d: Error validating %s: %v\n", workerID, path, err)
					continue
				}

				if isValid {
					mu.Lock()
					validFiles = append(validFiles, path)
					mu.Unlock()
				}

				// Increment processed count
				mu.Lock()
				fileProcessed++
				if s.progressChan != nil && fileProcessed%10 == 0 {
					s.progressChan <- fileProcessed
				}
				mu.Unlock()
			}
		}(i)
	}

	// Send paths to workers
	go func() {
		for _, path := range paths {
			filesChan <- path
		}
		close(filesChan)
	}()

	// Wait for all workers to complete
	wg.Wait()
	close(errorsChan)

	// Check for errors
	var lastError error
	for err := range errorsChan {
		// Just keep the last error
		lastError = err
	}

	// Report final progress
	if s.progressChan != nil {
		s.progressChan <- len(paths)
	}

	return validFiles, lastError
}

// validateFile checks if a file is valid for processing without reading the entire file
func (s *Scanner) validateFile(filePath string) (bool, error) {
	// Get file info
	info, err := os.Stat(filePath)
	if err != nil {
		return false, fmt.Errorf("unable to stat file: %v", err)
	}

	// Skip directories
	if info.IsDir() {
		return false, nil
	}

	// Skip files larger than the maximum size
	if info.Size() > s.maxFileSize {
		return false, nil
	}

	// Check if it's likely a text file (this is a more efficient check)
	isText, err := IsTextFile(filePath)
	if err != nil {
		return false, err
	}
	
	return isText, nil
}

// IsTextFile checks if a file is a text file
// This is important for filtering out binary files
func IsTextFile(filePath string) (bool, error) {
	// First, check extension - quick method
	ext := strings.ToLower(filepath.Ext(filePath))
	if supportedExts[ext] {
		// For more accurate checking, we sample the first few KB
		// This is more efficient than reading the whole file
		file, err := os.Open(filePath)
		if err != nil {
			return false, fmt.Errorf("failed to open file: %v", err)
		}
		defer file.Close()
		
		// Read the first 8KB to check if it's binary
		sampleSize := 8 * 1024
		sample := make([]byte, sampleSize)
		
		bytesRead, err := file.Read(sample)
		if err != nil && err.Error() != "EOF" {
			return false, fmt.Errorf("failed to read file: %v", err)
		}
		
		// If we couldn't read anything, treat as non-text
		if bytesRead == 0 {
			return false, nil
		}
		
		// Resize to actual bytes read
		sample = sample[:bytesRead]
		
		// Check for null bytes or high concentration of non-printable characters
		nullCount := 0
		nonPrintableCount := 0
		
		for _, b := range sample {
			if b == 0 {
				nullCount++
			}
			if (b < 8 || b > 13) && (b < 32 || b > 126) {
				nonPrintableCount++
			}
		}
		
		// If more than 5% are null bytes, consider it binary
		if nullCount > bytesRead/20 {
			return false, nil
		}
		
		// If more than 30% are non-printable (and not common control chars), consider it binary
		if nonPrintableCount > bytesRead*3/10 {
			return false, nil
		}
		
		return true, nil
	}
	
	return false, nil
}

// GetFileSize returns the size of a file in bytes
func GetFileSize(filePath string) (int64, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}
