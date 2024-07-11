package readenv

import (
	"bufio"
	"log"
	"os"
	"strings"
)

var (
	GithubClientID       string
	GithubClientSecret   string
	GoogleClientSecret   string
	GoogleClientID       string
	FacebookClientID     string
	FacebookClientSecret string
)

func LoadEnv() {
	file, err := os.Open(".env")
	if err != nil {
		log.Fatalf("Error opening .env file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		value := parts[1]
		os.Setenv(key, value)
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading .env file: %v", err)
	}

	GithubClientID = os.Getenv("GITHUB_CLIENT_ID")
	GithubClientSecret = os.Getenv("GITHUB_CLIENT_SECRET")
	GoogleClientID = os.Getenv("GOOGLE_CLIENT_ID")
	GoogleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	FacebookClientID = os.Getenv("FACEBOOK_CLIENT_ID")
	FacebookClientSecret = os.Getenv("FACEBOOK_CLIENT_SECRET")
}
