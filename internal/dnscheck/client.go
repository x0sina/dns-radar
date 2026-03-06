package dnscheck

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

type Result struct {
	OK       bool
	Duration time.Duration
	Records  []string
	Error    string
}

type Client struct {
	Timeout time.Duration
}

func New(timeout time.Duration) *Client {
	return &Client{Timeout: timeout}
}

func (c *Client) LookupTXT(ctx context.Context, serverIP, domain string) Result {
	start := time.Now()

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: c.Timeout}
			return dialer.DialContext(dialCtx, "udp", net.JoinHostPort(serverIP, "53"))
		},
	}

	queryCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	records, err := resolver.LookupTXT(queryCtx, domain)
	if err != nil {
		return Result{
			OK:       false,
			Duration: time.Since(start),
			Records:  nil,
			Error:    classifyError(err),
		}
	}

	return Result{
		OK:       true,
		Duration: time.Since(start),
		Records:  records,
		Error:    "-",
	}
}

func ContainsToken(records []string, token string) bool {
	if len(records) == 0 {
		return false
	}

	token = strings.TrimSpace(strings.ToLower(token))
	if token == "" {
		return true
	}

	for _, record := range records {
		if strings.Contains(strings.ToLower(record), token) {
			return true
		}
	}

	return false
}

func classifyError(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "TIMEOUT"
	case errors.Is(err, context.Canceled):
		return "CANCELED"
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout {
			return "TIMEOUT"
		}
		if dnsErr.IsNotFound {
			return "NXDOMAIN"
		}
		if dnsErr.Err != "" {
			return normalizeReason(dnsErr.Err)
		}
	}

	return "ERROR"
}

func normalizeReason(reason string) string {
	replacer := strings.NewReplacer(" ", "_", "-", "_", ":", "_", ".", "_")
	return strings.ToUpper(replacer.Replace(reason))
}
