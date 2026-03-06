package ping

import (
	"bytes"
	"context"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"time"
)

var ttlPattern = regexp.MustCompile(`(?i)ttl[=\s]`)

type Result struct {
	OK       bool
	Duration time.Duration
}

type Pinger struct {
	Timeout time.Duration
}

func New(timeout time.Duration) *Pinger {
	return &Pinger{Timeout: timeout}
}

func (p *Pinger) Once(ctx context.Context, ip string) Result {
	start := time.Now()
	callTimeout := p.Timeout + 800*time.Millisecond
	callCtx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	args := pingArgs(p.Timeout, ip)
	cmd := exec.CommandContext(callCtx, "ping", args...)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()

	output := out.String()
	ttlHit := ttlPattern.MatchString(output)

	ok := ttlHit || err == nil
	if callCtx.Err() != nil {
		ok = false
	}

	return Result{
		OK:       ok,
		Duration: time.Since(start),
	}
}

func pingArgs(timeout time.Duration, ip string) []string {
	switch runtime.GOOS {
	case "windows":
		return []string{"-n", "1", "-w", strconv.FormatInt(timeout.Milliseconds(), 10), ip}
	case "darwin":
		return []string{"-c", "1", "-W", strconv.FormatInt(timeout.Milliseconds(), 10), ip}
	default:
		seconds := int(timeout / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		return []string{"-c", "1", "-W", strconv.Itoa(seconds), ip}
	}
}
