package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

/*
Jotti Uploader - Tool to upload files to https://virusscan.jotti.org
Jotti is an alternative to VirusTotal
by cyclone
https://github.com/cyclone-github/jotti

changelog:
v2023-11-10.1800
	initial version
v2023-11-11.1800
	cleaned up code
	github release
v1.0.0; 2025-08-27
	stable v1.0.0 release
	enforce Jotti's 250MB max file limit
	added upload progress bar
	added HTTP client timeout to avoid hangs
	added non-zero exit on rate limit
	tidied up logic in URL, filename, directory parsing
*/

// global variables
var (
	jottiUploadURL         = "https://virusscan.jotti.org/en-US/submit-file"
	jottiChecksumURL       = "https://virusscan.jotti.org/en-US/search/hash/%s"
	httpClient             = &http.Client{Timeout: 30 * time.Second}
	maxUploadSize    int64 = 250 * 1024 * 1024 // enforce Jotti's 250MB max file limit
)

func versionFunc() {
	fmt.Fprintln(os.Stderr, "Jotti Uploader v1.0.0; 2025-08-27")
	fmt.Fprintln(os.Stderr, "https://github.com/cyclone-github/jotti")
}

// help function
func helpFunc() {
	versionFunc()
	str := "\nExample Usage:\n" +
		"\n./jotti {file_to_scan}\n" +
		"\n./jotti -help\n" +
		"\n./jotti -version\n"
	fmt.Fprintln(os.Stderr, str)
	os.Exit(0)
}

// calculate SHA1 checksum of file
func calculateSHA1Checksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha1.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

type progressReader struct {
	r        io.Reader
	total    int64
	read     int64
	lastTick time.Time
}

const progressBarWidth = 20

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.read += int64(n)
		now := time.Now()
		if now.Sub(p.lastTick) >= 150*time.Millisecond || p.read == p.total {
			p.render()
			p.lastTick = now
		}
	}

	if err == io.EOF {
		p.renderDone()
	}
	return n, err
}

func (p *progressReader) render() {
	percent := float64(p.read) * 100 / float64(p.total)
	filled := int(percent / (100 / progressBarWidth))
	if filled > progressBarWidth {
		filled = progressBarWidth
	}
	var bar [progressBarWidth]byte
	for i := 0; i < progressBarWidth; i++ {
		if i < filled {
			bar[i] = '='
		} else {
			bar[i] = ' '
		}
	}
	fmt.Fprintf(os.Stderr, "\rProgress: [%s] %6.2f%%", string(bar[:]), percent)
}

func (p *progressReader) renderDone() {
	var bar [progressBarWidth]byte
	for i := 0; i < progressBarWidth; i++ {
		bar[i] = '='
	}
	fmt.Fprintf(os.Stderr, "\rProgress: [%s] 100.00%% (sent) - waiting response...", string(bar[:]))
}

// upload file to Jotti
func uploadFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("sample-file[]", filepath.Base(filePath))
	if err != nil {
		return "", err
	}
	if _, err = io.Copy(part, file); err != nil {
		return "", err
	}
	if err = writer.Close(); err != nil {
		return "", err
	}

	raw := body.Bytes()
	pr := &progressReader{
		r:     bytes.NewReader(raw),
		total: int64(len(raw)),
	}

	request, err := http.NewRequest("POST", jottiUploadURL, pr)
	if err != nil {
		return "", err
	}
	request.Header.Add("Content-Type", writer.FormDataContentType())
	request.ContentLength = int64(len(raw))

	response, err := httpClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non-200 response status: %d", response.StatusCode)
	}

	return "", nil
}

// check if SHA1 checksum exists on Jotti
func checkJottiSearch(checksum string) (bool, string, error) {
	searchURL := fmt.Sprintf(jottiChecksumURL, checksum)

	response, err := httpClient.Get(searchURL)
	if err != nil {
		return false, "", err
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(response.Body)
		if err != nil {
			return false, "", err
		}
		body := string(bodyBytes)

		if strings.Contains(body, "Too many requests") {
			// rate limit detected, exit
			fmt.Fprintln(os.Stderr, "Rate limited by Jotti. Please try again in a few minutes.")
			os.Exit(2)
		}

		// search for "Hash not found" string
		if strings.Contains(body, "Hash not found") {
			return false, searchURL, nil
		}
		return true, searchURL, nil
	}

	return false, "", fmt.Errorf("unexpected response status: %d", response.StatusCode)
}

func main() {
	help := flag.Bool("help", false, "Prints help:")
	version := flag.Bool("version", false, "Program Version:")
	cyclone := flag.Bool("cyclone", false, "")
	flag.Parse()
	if *version {
		versionFunc()
		os.Exit(0)
	}
	if *cyclone {
		fmt.Fprintln(os.Stderr, "Coded by cyclone ;)")
		os.Exit(0)
	}

	// check for file in cli
	if len(os.Args) < 2 {
		log.Fatal("Usage: ./jotti <file_to_scan>")
	}
	if *help {
		helpFunc()
	}

	// loop over each file
	for _, filePath := range os.Args[1:] {
		// enforce Jotti's 250MB max file limit before hashing/upload
		fi, err := os.Stat(filePath)
		if err != nil {
			log.Printf("Error stat %s: %v\n", filePath, err)
			continue
		}
		if fi.IsDir() {
			log.Printf("Skipping directory: %s\n", filePath)
			continue
		}
		if fi.Size() > maxUploadSize {
			log.Printf("Skipping %s: file size %d exceeds 250MB limit\n", filePath, fi.Size())
			continue
		}

		// calculate SHA1 checksum of file
		checksum, err := calculateSHA1Checksum(filePath)
		if err != nil {
			log.Printf("Error calculating SHA1 checksum for %s: %v\n", filePath, err)
			continue
		}
		fmt.Printf("SHA1 Checksum: %s\n", checksum)

		// check if SHA1 checksum is on Jotti
		found, jottiURL, err := checkJottiSearch(checksum)
		if err != nil {
			log.Printf("Error checking Jotti's malware scan: %v\n", err)
			continue
		}

		if found {
			fmt.Printf("File %s found on Jotti:\n%s\n", filePath, jottiURL)
			continue // skip to next file if found
		}

		fmt.Printf("Uploading %s: ", filePath)
		_, err = uploadFile(filePath)
		if err != nil {
			log.Printf("Error: %v\n", err)
			continue
		}

		fmt.Println("OK")
		fmt.Println(fmt.Sprintf(jottiChecksumURL, checksum))

		// wait for nth sec
		time.Sleep(1000 * time.Millisecond)
	}
}

// end code
