[![Readme Card](https://github-readme-stats.vercel.app/api/pin/?username=cyclone-github&repo=jotti&theme=gruvbox)](https://github.com/cyclone-github/jotti/)

[![Go Report Card](https://goreportcard.com/badge/github.com/cyclone-github/jotti)](https://goreportcard.com/report/github.com/cyclone-github/jotti)
[![GitHub issues](https://img.shields.io/github/issues/cyclone-github/jotti.svg)](https://github.com/cyclone-github/jotti/issues)
[![License](https://img.shields.io/github/license/cyclone-github/jotti.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/cyclone-github/jotti.svg)](https://github.com/cyclone-github/jotti/releases)

# jotti

```
$ ./jotti_amd64.bin jotti_amd64.exe
SHA1 Checksum: 7bbaea591789073aaf96ce2669e6238196cb9093
Progress: [====================] 100.00% (sent) - waiting response...OK
https://virusscan.jotti.org/en-US/search/hash/7bbaea591789073aaf96ce2669e6238196cb9093
```
### About:
- This tool is a CLI file uploader for Jotti https://virusscan.jotti.org
- Jotti is a lesser-known alternative to VirusTotal
- Jotti enforces a rate limit which this tool honors once it has been reached. If you need to scan more files, consider supporting the Jotti project by purchasing an API key. 
### Usage Instructions:
```
./jotti {file_to_scan}
./jotti -help
./jotti -version
```
### Compile jotti from source:
- If you want the latest features, compiling from source is the best option since the release version may run several revisions behind the source code.
- This assumes you have Go and Git installed
  - `git clone https://github.com/cyclone-github/jotti.git`  # clone repo
  - `cd jotti`                                               # enter project directory
  - `go mod init jotti`                                      # initialize Go module (skips if go.mod exists)
  - `go mod tidy`                                              # download dependencies
  - `go build -ldflags="-s -w" .`                              # compile binary in current directory
  - `go install -ldflags="-s -w" .`                            # compile binary and install to $GOPATH
- Compile from source code how-to:
  - https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt

### Changelog:
- https://github.com/cyclone-github/jotti/blob/main/CHANGELOG.md