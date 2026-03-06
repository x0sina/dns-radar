package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultQueryCount      = 5
	defaultMinSuccess      = 4
	defaultMinDomainLength = 152
	defaultMaxDomainLength = 253
	defaultPingTimeoutMS   = 2000
	defaultDNSTimeoutMS    = 2000
	defaultConcurrency     = 64
)

type Config struct {
	IPSFile         string
	SuccessFile     string
	SuccessCSVFile  string
	BaseDomain      string
	ExpectedToken   string
	QueryCount      int
	MinSuccess      int
	MinDomainLength int
	MaxDomainLength int
	MixedCaseProbes bool
	PingTimeout     time.Duration
	DNSTimeout      time.Duration
	Concurrency     int
}

func Load() (Config, error) {
	if err := loadDotEnvIfPresent(
		".env",
		filepath.Join("dns-radar", ".env"),
		filepath.Join("..", ".env"),
	); err != nil {
		return Config{}, err
	}

	cfg := Config{
		IPSFile:         firstExistingPath("ips.txt", filepath.Join("..", "ips.txt")),
		SuccessFile:     firstExistingPath("good.txt", filepath.Join("..", "good.txt")),
		SuccessCSVFile:  firstExistingPath("good.csv", filepath.Join("..", "good.csv")),
		QueryCount:      defaultQueryCount,
		MinSuccess:      defaultMinSuccess,
		MinDomainLength: defaultMinDomainLength,
		MaxDomainLength: defaultMaxDomainLength,
		MixedCaseProbes: true,
		PingTimeout:     time.Duration(defaultPingTimeoutMS) * time.Millisecond,
		DNSTimeout:      time.Duration(defaultDNSTimeoutMS) * time.Millisecond,
		Concurrency:     defaultConcurrency,
	}

	if value := strings.TrimSpace(os.Getenv("IPS_FILE")); value != "" {
		cfg.IPSFile = value
	}
	if value := strings.TrimSpace(os.Getenv("SUCCESS_FILE")); value != "" {
		cfg.SuccessFile = value
	}
	if value := strings.TrimSpace(os.Getenv("SUCCESS_CSV_FILE")); value != "" {
		cfg.SuccessCSVFile = value
	}

	cfg.BaseDomain = normalizeDomain(os.Getenv("TXT_BASE_DOMAIN"))
	cfg.ExpectedToken = strings.TrimSpace(os.Getenv("TXT_EXPECTED_TOKEN"))

	if cfg.BaseDomain == "" {
		return Config{}, errors.New("TXT_BASE_DOMAIN is required (example: probe.example.com)")
	}

	var err error
	if cfg.QueryCount, err = intEnv("DNS_QUERY_COUNT", cfg.QueryCount, 1, 20); err != nil {
		return Config{}, err
	}
	if cfg.MinSuccess, err = intEnv("DNS_MIN_SUCCESS", cfg.MinSuccess, 1, cfg.QueryCount); err != nil {
		return Config{}, err
	}
	if cfg.MinDomainLength, err = intEnv("DNS_MIN_LENGTH", cfg.MinDomainLength, 152, 253); err != nil {
		return Config{}, err
	}
	if cfg.MaxDomainLength, err = intEnv("DNS_MAX_LENGTH", cfg.MaxDomainLength, cfg.MinDomainLength, 253); err != nil {
		return Config{}, err
	}
	if cfg.Concurrency, err = intEnv("SCAN_CONCURRENCY", cfg.Concurrency, 1, 2000); err != nil {
		return Config{}, err
	}

	if cfg.MixedCaseProbes, err = boolEnv("DNS_MIXED_CASE", cfg.MixedCaseProbes); err != nil {
		return Config{}, err
	}

	pingMS, err := intEnv("PING_TIMEOUT_MS", int(cfg.PingTimeout/time.Millisecond), 100, 30000)
	if err != nil {
		return Config{}, err
	}
	cfg.PingTimeout = time.Duration(pingMS) * time.Millisecond

	dnsMS, err := intEnv("DNS_TIMEOUT_MS", int(cfg.DNSTimeout/time.Millisecond), 100, 30000)
	if err != nil {
		return Config{}, err
	}
	cfg.DNSTimeout = time.Duration(dnsMS) * time.Millisecond

	return cfg, nil
}

func intEnv(name string, fallback, min, max int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}

	value, err := strconv.Atoi(raw)
	if err != nil || value < min || value > max {
		return 0, fmt.Errorf("%s must be an integer in [%d, %d], got %q", name, min, max, raw)
	}

	return value, nil
}

func boolEnv(name string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if raw == "" {
		return fallback, nil
	}

	switch raw {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be boolean-like (true/false), got %q", name, raw)
	}
}

func firstExistingPath(candidates ...string) string {
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	if len(candidates) == 0 {
		return ""
	}
	return candidates[0]
}

func normalizeDomain(domain string) string {
	trimmed := strings.TrimSpace(strings.ToLower(domain))
	return strings.TrimRight(trimmed, ".")
}

func loadDotEnvIfPresent(candidates ...string) error {
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}

		file, err := os.Open(candidate)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("open %s: %w", candidate, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			if strings.HasPrefix(line, "export ") {
				line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
			}

			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				return fmt.Errorf("%s:%d invalid env line %q", candidate, lineNo, line)
			}

			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if key == "" {
				return fmt.Errorf("%s:%d empty env key", candidate, lineNo)
			}

			if len(value) >= 2 {
				if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
					value = value[1 : len(value)-1]
				}
			}

			if _, exists := os.LookupEnv(key); exists {
				continue
			}

			if err := os.Setenv(key, value); err != nil {
				return fmt.Errorf("%s:%d set %s: %w", candidate, lineNo, key, err)
			}
		}

		if err := scanner.Err(); err != nil {
			return fmt.Errorf("read %s: %w", candidate, err)
		}

		return nil
	}

	return nil
}
