package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

type Match struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
}

type Summary struct {
	GoogleKeys   int `json:"google_keys"`
	StripeKeys   int `json:"stripe_keys"`
	SupabaseKeys int `json:"supabase_keys"`
}

type Result struct {
	Target  string  `json:"target"`
	Summary Summary `json:"summary"`
	Matches []Match `json:"matches"`
}

var patterns = []struct {
	Name  string
	Regex *regexp.Regexp
}{
	{Name: "google_api_key", Regex: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{Name: "stripe_live_key", Regex: regexp.MustCompile(`sk_live_[0-9A-Za-z]{16,}`)},
	{Name: "supabase_key", Regex: regexp.MustCompile(`supabase_key[_=:"'\s-]*[0-9A-Za-z\-_]{20,}`)},
}

func main() {
	target := flag.String("target", "", "directory to scan")
	flag.Parse()

	if *target == "" {
		writeError(errors.New("target is required"))
		os.Exit(1)
	}

	info, err := os.Stat(*target)
	if err != nil {
		writeError(err)
		os.Exit(1)
	}
	if !info.IsDir() {
		writeError(errors.New("target must be a directory"))
		os.Exit(1)
	}

	result := Result{Target: *target, Matches: []Match{}}
	err = filepath.WalkDir(*target, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "__pycache__":
				return filepath.SkipDir
			}
			return nil
		}
		return scanFile(*target, path, &result)
	})
	if err != nil {
		writeError(err)
		os.Exit(1)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		writeError(err)
		os.Exit(1)
	}
}

func scanFile(root string, path string, result *Result) error {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	relPath, err := filepath.Rel(root, path)
	if err != nil {
		relPath = path
	}

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		for _, pattern := range patterns {
			found := pattern.Regex.FindAllString(line, -1)
			for _, value := range found {
				result.Matches = append(result.Matches, Match{
					Type:    pattern.Name,
					Value:   value,
					File:    relPath,
					Line:    lineNumber,
					Snippet: limitSnippet(line),
				})
				switch pattern.Name {
				case "google_api_key":
					result.Summary.GoogleKeys++
				case "stripe_live_key":
					result.Summary.StripeKeys++
				case "supabase_key":
					result.Summary.SupabaseKeys++
				}
			}
		}
	}

	return scanner.Err()
}

func limitSnippet(line string) string {
	if len(line) <= 200 {
		return line
	}
	return fmt.Sprintf("%s...", line[:200])
}

func writeError(err error) {
	_ = json.NewEncoder(os.Stderr).Encode(map[string]string{
		"error": err.Error(),
	})
}
