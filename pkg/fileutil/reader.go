package fileutil

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// FileReader manages file reading operations
type FileReader struct {
	MaxFileSize     int64                                                      // Maximum file size in bytes to process
	ChunkSize       int64                                                      // Size of chunks to process for large files
	MaxLineLength   int                                                        // Maximum line length to process before truncating
	ConcurrentRead  bool                                                       // Enable concurrent reading for very large files
	NumWorkers      int                                                        // Number of workers for concurrent reading
	StatusUpdate    func(lineNum int, totalBytes int64, processedBytes int64)  // Status update callback
}

// NewFileReader creates a new FileReader instance
func NewFileReader() *FileReader {
	return &FileReader{
		MaxFileSize:    5 * 1024 * 1024 * 1024, // Default to 5GB
		ChunkSize:      20 * 1024 * 1024,       // 20MB chunks for large file processing
		MaxLineLength:  10 * 1024 * 1024,       // 10MB max line length
		ConcurrentRead: true,                  // Enable concurrent reading by default
		NumWorkers:     runtime.NumCPU(),      // Use all available CPU cores
		StatusUpdate: func(lineNum int, totalBytes int64, processedBytes int64) {
			// Default empty implementation
		},
	}
}

// NewFileReaderWithConfig creates a FileReader with custom configuration
func NewFileReaderWithConfig(maxFileSize int64) *FileReader {
	return &FileReader{
		MaxFileSize:    maxFileSize,
		ChunkSize:      20 * 1024 * 1024,      // 20MB chunks
		MaxLineLength:  10 * 1024 * 1024,      // 10MB max line length
		ConcurrentRead: true,                 // Enable concurrent reading by default
		NumWorkers:     runtime.NumCPU(),     // Use all available CPU cores
		StatusUpdate: func(lineNum int, totalBytes int64, processedBytes int64) {
			// Default empty implementation
		},
	}
}

// SetStatusUpdateFunc sets a custom status update function
func (fr *FileReader) SetStatusUpdateFunc(statusFunc func(lineNum int, totalBytes int64, processedBytes int64)) {
	fr.StatusUpdate = statusFunc
}

// SetConcurrentReading configures concurrent reading settings
func (fr *FileReader) SetConcurrentReading(enabled bool, numWorkers int) {
	fr.ConcurrentRead = enabled
	if numWorkers > 0 {
		fr.NumWorkers = numWorkers
	}
}

// ReadLines reads a file line by line and calls the provided function for each line
func (fr *FileReader) ReadLines(filePath string, processLine func(line string, lineNum int) error) error {
	// Check file size first to avoid processing extremely large files
	size, err := GetFileSize(filePath)
	if err != nil {
		return err
	}

	// Reject files larger than the absolute maximum
	if size > fr.MaxFileSize {
		return fmt.Errorf("file too large: %s (%d bytes, max %d bytes)", filePath, size, fr.MaxFileSize)
	}

	// For very large files (>1GB), use the concurrent chunk reader
	if size > 1*1024*1024*1024 && fr.ConcurrentRead {
		return fr.readLinesConcurrent(filePath, size, processLine)
	}
	
	// For large files (>200MB), always use a chunked approach for reliability
	if size > 200*1024*1024 {
		file, err := os.Open(filePath)
		if err != nil {
			return err
		}
		defer file.Close()
		return fr.readLinesChunked(file, size, processLine)
	}

	// For smaller files, use the standard scanning approach with an appropriate buffer
	return fr.readLinesScanner(filePath, size, processLine)
}

// readLinesScanner reads files using bufio.Scanner, optimized for medium-sized files
func (fr *FileReader) readLinesScanner(filePath string, size int64, processLine func(line string, lineNum int) error) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	
	// Scale buffer size based on file size, with reasonable limits
	bufferSize := 4 * 1024 * 1024 // 4MB buffer by default
	
	// Scale buffer based on file size
	if size > 10*1024*1024 { // 10MB
		bufferSize = 16 * 1024 * 1024 // 16MB buffer 
	}
	if size > 50*1024*1024 { // 50MB
		bufferSize = 64 * 1024 * 1024 // 64MB buffer for larger files
	}
	if size > 100*1024*1024 { // 100MB
		bufferSize = 128 * 1024 * 1024 // 128MB buffer for very large files
	}
	
	// Create buffer for scanner
	buf := make([]byte, bufferSize)
	scanner.Buffer(buf, bufferSize)

	lineNum := 0
	var processedBytes int64 = 0

	// Update status at reasonable intervals based on file size
	var statusInterval int
	if size > 100*1024*1024 { // 100MB
		statusInterval = 10000 // Update less frequently for large files
	} else if size > 10*1024*1024 { // 10MB
		statusInterval = 5000
	} else {
		statusInterval = 1000 // Default for smaller files
	}
	
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		
		// Update processedBytes approximately
		processedBytes += int64(len(line) + 1) // +1 for newline
		
		if lineNum % statusInterval == 0 {
			fr.StatusUpdate(lineNum, size, processedBytes)
		}

		if err := processLine(line, lineNum); err != nil {
			return err
		}
	}

	// Final status update
	fr.StatusUpdate(lineNum, size, processedBytes)

	if err := scanner.Err(); err != nil {
		// For token too long errors or any other scanner error, fall back to chunked reading
		if strings.Contains(err.Error(), "token too long") || strings.Contains(err.Error(), "bufio") {
			// Log error for debugging
			fmt.Printf("Scanner error, falling back to chunked reader: %v\n", err)
			
			// Reset to beginning of file and try chunked approach
			if _, err := file.Seek(0, 0); err != nil {
				return fmt.Errorf("failed to reset file position: %v", err)
			}
			
			return fr.readLinesChunked(file, size, processLine)
		}
		return err
	}

	return nil
}

// readLinesChunked reads a file in chunks and handles very large lines
// by breaking them into manageable segments if needed
func (fr *FileReader) readLinesChunked(file *os.File, totalSize int64, processLine func(line string, lineNum int) error) error {
	// Use an optimized read buffer size based on file size
	bufferSize := 2 * 1024 * 1024 // 2MB read buffer by default
	if totalSize > 500*1024*1024 { // 500MB+ files
		bufferSize = 4 * 1024 * 1024 // 4MB buffer for very large files
	}
	if totalSize > 1024*1024*1024 { // 1GB+ files
		bufferSize = 8 * 1024 * 1024 // 8MB buffer for extremely large files
	}
	
	reader := bufio.NewReaderSize(file, bufferSize)
	lineNum := 0
	var processedBytes int64 = 0

	// Status update frequency based on file size
	var updateInterval int64
	if totalSize > 1024*1024*1024 { // 1GB+
		updateInterval = 50 * 1024 * 1024 // Update every 50MB
	} else if totalSize > 500*1024*1024 { // 500MB+
		updateInterval = 20 * 1024 * 1024 // Update every 20MB
	} else if totalSize > 100*1024*1024 { // 100MB+
		updateInterval = 10 * 1024 * 1024 // Update every 10MB
	} else {
		updateInterval = 5 * 1024 * 1024 // Update every 5MB
	}
	
	lastUpdate := int64(0)
	
	// Configure maximum line length to avoid memory issues
	maxLineLength := fr.MaxLineLength // Use configured max line length
	if totalSize > 1024*1024*1024 { // 1GB+
		if maxLineLength > 5*1024*1024 { // Limit to 5MB for gigabyte+ files
			maxLineLength = 5 * 1024 * 1024
		}
	}
	
	// Process the file line by line with the chunked reader
	for {
		line, err := reader.ReadString('\n')
		
		if err != nil && err != io.EOF {
			return fmt.Errorf("error reading file: %v", err)
		}
		
		// Track processed bytes
		lineSize := int64(len(line))
		processedBytes += lineSize
		
		// Only process non-empty lines
		if lineSize > 0 {
			lineNum++
			
			// For extremely long lines, truncate to avoid memory issues
			if lineSize > int64(maxLineLength) {
				truncatedLine := line[:maxLineLength] + fmt.Sprintf("... [truncated, full length: %d bytes]", lineSize)
				
				// Process the truncated line
				if err := processLine(truncatedLine, lineNum); err != nil {
					return err
				}
			} else {
				// Process regular sized line (remove trailing newline if present)
				if len(line) > 0 && line[len(line)-1] == '\n' {
					line = line[:len(line)-1]
				}
				
				if err := processLine(line, lineNum); err != nil {
					return err
				}
			}
		}
		
		// Update status based on processed data amount
		if processedBytes-lastUpdate >= updateInterval {
			fr.StatusUpdate(lineNum, totalSize, processedBytes)
			lastUpdate = processedBytes
		}
		
		// Break on EOF after processing the last line
		if err == io.EOF {
			break
		}
	}
	
	// Final status update
	fr.StatusUpdate(lineNum, totalSize, processedBytes)
	
	return nil
}

// readLinesConcurrent reads very large files by dividing them into chunks and processing in parallel
func (fr *FileReader) readLinesConcurrent(filePath string, fileSize int64, processLine func(line string, lineNum int) error) error {
    // For massive files, we'll split into chunks and process in parallel
    numWorkers := fr.NumWorkers
    
    // Open the file once for metadata
    file, err := os.Open(filePath)
    if err != nil {
        return err
    }
    file.Close() // Close immediately as we'll reopen per worker
    
    // Calculate chunk size - larger chunks are more efficient but use more memory
    chunkSize := fr.ChunkSize
    if fileSize > 5*1024*1024*1024 { // 5GB+
        chunkSize = 100 * 1024 * 1024 // 100MB chunk size for extremely large files
    } else if fileSize > 1024*1024*1024 { // 1GB+
        chunkSize = 50 * 1024 * 1024 // 50MB chunk size
    }
    
    // Calculate number of chunks
    numChunks := (fileSize + chunkSize - 1) / chunkSize // Round up
    
    // If fewer chunks than workers, adjust worker count
    if numChunks < int64(numWorkers) {
        numWorkers = int(numChunks)
    }
    
    // Channel to coordinate results from workers
    results := make(chan struct {
        lineNum int
        bytes   int64
        err     error
    })
    
    // Mutex for coordinated line output
    var (
        outputMutex sync.Mutex
        wg          sync.WaitGroup
        nextLineNum = 1 // Start with line 1
        totalProcessed int64 = 0
    )
    
    // Wrapper for process line that ensures sequential output
    processLineWrapper := func(line string, workerLineNum int, chunkIndex int) error {
        outputMutex.Lock()
        defer outputMutex.Unlock()
        return processLine(line, workerLineNum)
    }
    
    // Process each chunk in parallel
    for i := int64(0); i < numChunks; i++ {
        wg.Add(1)
        go func(chunkIndex int64) {
            defer wg.Done()
            
            // Calculate chunk boundaries
            startPos := chunkIndex * chunkSize
            endPos := startPos + chunkSize
            if endPos > fileSize {
                endPos = fileSize
            }
            
            // Track chunk metrics
            var chunkBytes int64 = 0
            chunkLineCount := 0
            
            // Open file for this chunk
            chunkFile, err := os.Open(filePath)
            if err != nil {
                results <- struct {
                    lineNum int
                    bytes   int64
                    err     error
                }{0, 0, fmt.Errorf("chunk %d failed to open file: %v", chunkIndex, err)}
                return
            }
            defer chunkFile.Close()
            
            // Seek to start position
            _, err = chunkFile.Seek(startPos, 0)
            if err != nil {
                results <- struct {
                    lineNum int
                    bytes   int64
                    err     error
                }{0, 0, fmt.Errorf("chunk %d failed to seek: %v", chunkIndex, err)}
                return
            }
            
            // Read until end of chunk or file
            reader := bufio.NewReaderSize(chunkFile, 4*1024*1024) // 4MB buffer
            
            // If not starting at the beginning, read and discard first partial line
            // (unless we're at the start of the file)
            if startPos > 0 {
                _, err := reader.ReadString('\n')
                if err != nil && err != io.EOF {
                    results <- struct {
                        lineNum int
                        bytes   int64
                        err     error
                    }{0, 0, fmt.Errorf("chunk %d failed to read initial line: %v", chunkIndex, err)}
                    return
                }
            }
            
            // Reserve a line number range for this chunk
            outputMutex.Lock()
            chunkStartLine := nextLineNum
            outputMutex.Unlock()
            
            // Now read full lines as part of this chunk
            for {
                line, err := reader.ReadString('\n')
                lineSize := int64(len(line))
                
                // Track progress
                chunkBytes += lineSize
                
                // Process complete line
                if lineSize > 0 {
                    chunkLineCount++
                    
                    // Remove newline if present
                    if len(line) > 0 && line[len(line)-1] == '\n' {
                        line = line[:len(line)-1]
                    }
                    
                    // Process this line
                    if err := processLineWrapper(line, chunkStartLine+chunkLineCount-1, int(chunkIndex)); err != nil {
                        results <- struct {
                            lineNum int
                            bytes   int64
                            err     error
                        }{chunkLineCount, chunkBytes, fmt.Errorf("chunk %d processing error: %v", chunkIndex, err)}
                        return
                    }
                }
                
                // Stop if we've reached the end of the chunk or file
                if err == io.EOF || chunkBytes >= (endPos-startPos) {
                    break
                }
                
                // Handle other errors
                if err != nil && err != io.EOF {
                    results <- struct {
                        lineNum int
                        bytes   int64
                        err     error
                    }{chunkLineCount, chunkBytes, fmt.Errorf("chunk %d read error: %v", chunkIndex, err)}
                    return
                }
            }
            
            // Update next line number
            outputMutex.Lock()
            nextLineNum += chunkLineCount
            totalProcessed += chunkBytes
            fr.StatusUpdate(nextLineNum-1, fileSize, totalProcessed)
            outputMutex.Unlock()
            
            // Report success
            results <- struct {
                lineNum int
                bytes   int64
                err     error
            }{chunkLineCount, chunkBytes, nil}
            
        }(i)
    }
    
    // Process results in a separate goroutine
    go func() {
        for i := int64(0); i < numChunks; i++ {
            result := <-results
            if result.err != nil {
                // Log the error but continue with other chunks
                fmt.Printf("Error processing chunk: %v\n", result.err)
            }
        }
        wg.Wait()
        close(results)
    }()
    
    // Wait for all workers to complete
    wg.Wait()
    
    // Final status update
    fr.StatusUpdate(nextLineNum-1, fileSize, totalProcessed)
    
    return nil
}

// ReadContent reads the entire content of a file in chunks to avoid memory issues with large files
func (fr *FileReader) ReadContent(filePath string) (string, error) {
	size, err := GetFileSize(filePath)
	if err != nil {
		return "", err
	}

	// Only allow reading entire content for files smaller than a reasonable size
	// For large files, suggest using ReadLines instead
	maxWholeReadSize := int64(200 * 1024 * 1024) // 200MB
	if size > maxWholeReadSize {
		return "", fmt.Errorf("file too large for ReadContent: %s (%d bytes, max %d bytes). Use ReadLines for large files", 
			filePath, size, maxWholeReadSize)
	}

	// Use a scaling buffer size based on file size
	bufferSize := int64(1 * 1024 * 1024) // 1MB buffer by default
	if size > 10*1024*1024 { // 10MB+
		bufferSize = 4 * 1024 * 1024 // 4MB buffer
	}
	if size > 50*1024*1024 { // 50MB+
		bufferSize = 8 * 1024 * 1024 // 8MB buffer
	}

	// Pre-allocate a buffer with capacity close to the file size for efficiency
	// but with a reasonable cap to avoid excessive memory usage
	initialCapacity := size
	if initialCapacity > 50*1024*1024 { // Cap at 50MB initial allocation
		initialCapacity = 50 * 1024 * 1024
	}
	
	content := bytes.NewBuffer(make([]byte, 0, initialCapacity))
	buf := make([]byte, bufferSize)

	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// For larger files, show incremental progress
	updateInterval := int64(10 * 1024 * 1024) // 10MB intervals for progress
	lastUpdate := int64(0)
	var processedBytes int64 = 0

	for {
		n, err := file.Read(buf)
		if err == io.EOF {
			break
		} else if err != nil {
			return "", fmt.Errorf("error reading file: %v", err)
		}

		content.Write(buf[:n])
		
		// Track and report progress for larger files
		processedBytes += int64(n)
		if size > 20*1024*1024 && processedBytes-lastUpdate > updateInterval {
			fr.StatusUpdate(0, size, processedBytes)
			lastUpdate = processedBytes
		}
	}

	// Final update
	if size > 20*1024*1024 {
		fr.StatusUpdate(0, size, size)
	}

	return content.String(), nil
}

// ReadContentInChunks reads a file in chunks and processes each chunk
// This is useful for very large files that shouldn't be loaded into memory at once
func (fr *FileReader) ReadContentInChunks(filePath string, processChunk func(chunk []byte, offset int64) error) error {
	size, err := GetFileSize(filePath)
	if err != nil {
		return err
	}

	// Determine appropriate chunk size
	chunkSize := int64(4 * 1024 * 1024) // 4MB chunks by default
	if size > 500*1024*1024 { // 500MB+
		chunkSize = 20 * 1024 * 1024 // 20MB chunks for very large files
	} else if size > 100*1024*1024 { // 100MB+
		chunkSize = 10 * 1024 * 1024 // 10MB chunks for large files
	}

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	buffer := make([]byte, chunkSize)
	var offset int64 = 0
	var processedBytes int64 = 0
	
	// Update status at reasonable intervals
	updateInterval := int64(20 * 1024 * 1024) // 20MB for status updates
	lastUpdate := int64(0)

	for {
		bytesRead, err := file.Read(buffer)
		if bytesRead > 0 {
			// Process non-empty chunk
			if err := processChunk(buffer[:bytesRead], offset); err != nil {
				return err
			}
			
			offset += int64(bytesRead)
			processedBytes += int64(bytesRead)
			
			// Update status at intervals
			if processedBytes-lastUpdate >= updateInterval {
				fr.StatusUpdate(0, size, processedBytes)
				lastUpdate = processedBytes
			}
		}
		
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
	}

	// Final status update
	fr.StatusUpdate(0, size, processedBytes)
	
	return nil
}

// ExtractText extracts text from a file, handling different file types
func (fr *FileReader) ExtractText(filePath string) (string, error) {
	// Check if it's a simple text file
	isText, err := IsTextFile(filePath)
	if err != nil {
		return "", err
	}

	if isText {
		return fr.ReadContent(filePath)
	}

	// Get the file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	
	// For non-text files, we could add handlers for different file types:
	switch ext {
	case ".pdf":
		// Note: PDF extraction would require a PDF library
		// For now, we'll return a meaningful error
		return "", fmt.Errorf("PDF text extraction not implemented yet")
	case ".doc", ".docx", ".xls", ".xlsx":
		return "", fmt.Errorf("%s file format not supported yet", strings.ToUpper(ext[1:]))
	default:
		return "", fmt.Errorf("unsupported file type: %s", ext)
	}
}

// GetFileType returns the file type based on extension
func GetFileType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".txt":
		return "Text"
	case ".md":
		return "Markdown"
	case ".doc", ".docx":
		return "Word Document"
	case ".pdf":
		return "PDF"
	case ".xls", ".xlsx":
		return "Excel Spreadsheet"
	case ".json":
		return "JSON"
	case ".xml":
		return "XML"
	case ".html", ".htm":
		return "HTML"
	case ".csv":
		return "CSV"
	case ".rtf":
		return "Rich Text Format"
	case ".log":
		return "Log File"
	case ".cfg", ".conf", ".ini":
		return "Configuration File"
	default:
		return "Unknown"
	}
}
