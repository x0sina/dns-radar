package scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"dns-radar/internal/config"
	"dns-radar/internal/dnscheck"
	"dns-radar/internal/iplist"
	"dns-radar/internal/ping"
	"dns-radar/internal/probe"
)

type Scanner struct {
	cfg    config.Config
	probes []probe.DomainProbe
	dns    *dnscheck.Client
	pinger *ping.Pinger
}

func New(cfg config.Config) (*Scanner, error) {
	probes, err := probe.Generate(probe.Options{
		BaseDomain:      cfg.BaseDomain,
		Count:           cfg.QueryCount,
		MinDomainLength: cfg.MinDomainLength,
		MaxDomainLength: cfg.MaxDomainLength,
		MixedCase:       cfg.MixedCaseProbes,
	})
	if err != nil {
		return nil, err
	}

	return &Scanner{
		cfg:    cfg,
		probes: probes,
		dns:    dnscheck.New(cfg.DNSTimeout),
		pinger: ping.New(cfg.PingTimeout),
	}, nil
}

func (s *Scanner) Run(ctx context.Context) error {
	ips, err := iplist.Read(s.cfg.IPSFile)
	if err != nil {
		return fmt.Errorf("read ips file: %w", err)
	}

	successWriter, err := newSuccessWriter(s.cfg.SuccessFile)
	if err != nil {
		return fmt.Errorf("open success file: %w", err)
	}
	detailWriter, err := newSuccessCSVWriter(s.cfg.SuccessCSVFile)
	if err != nil {
		_ = successWriter.Close()
		return fmt.Errorf("open csv detail file: %w", err)
	}

	fmt.Println("Starting TXT scan for slipstream/dnstt DNS suitability")
	fmt.Printf("Reading IPs from: %s\n", s.cfg.IPSFile)
	fmt.Printf("Streaming successful servers to: %s\n", s.cfg.SuccessFile)
	fmt.Printf("Streaming successful details to: %s\n", s.cfg.SuccessCSVFile)
	fmt.Printf("Probe base domain: %s\n", s.cfg.BaseDomain)
	fmt.Printf("Probe lengths: %s\n", s.probeLengths())

	caseMode := "lowercase queries"
	if s.cfg.MixedCaseProbes {
		caseMode = "mixed-case queries"
	}
	fmt.Printf("Probe case mode: %s\n", caseMode)

	if s.cfg.ExpectedToken == "" {
		fmt.Println("TXT validation: any non-empty TXT answer")
	} else {
		fmt.Printf("TXT validation: must include %q (case-insensitive match)\n", s.cfg.ExpectedToken)
	}

	fmt.Printf(
		"Server pass rule: %d/%d successful TXT responses\n",
		s.cfg.MinSuccess,
		s.cfg.QueryCount,
	)
	fmt.Printf("Loaded %d IP(s). Concurrency: %d\n\n", len(ips), s.cfg.Concurrency)

	results, scanErr := s.scanAll(ctx, ips, successWriter, detailWriter)

	closeErr := successWriter.Close()
	csvCloseErr := detailWriter.Close()
	if scanErr != nil {
		if closeErr != nil || csvCloseErr != nil {
			return fmt.Errorf("%w (close txt: %v, close csv: %v)", scanErr, closeErr, csvCloseErr)
		}
		return scanErr
	}
	if closeErr != nil || csvCloseErr != nil {
		return fmt.Errorf("close output files failed (txt: %v, csv: %v)", closeErr, csvCloseErr)
	}

	successCount := 0
	for _, result := range results {
		if result.Passed {
			successCount++
		}
	}

	fmt.Printf("\nScan complete. %d success(es) written to: %s\n", successCount, s.cfg.SuccessFile)
	return nil
}

func (s *Scanner) probeLengths() string {
	parts := make([]string, 0, len(s.probes))
	for _, p := range s.probes {
		parts = append(parts, fmt.Sprintf("%d", p.Length))
	}
	return strings.Join(parts, ", ")
}

func (s *Scanner) scanAll(
	ctx context.Context,
	ips []string,
	successWriter *successWriter,
	detailWriter *successCSVWriter,
) ([]ipScanResult, error) {
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make([]ipScanResult, len(ips))
	if len(ips) == 0 {
		return results, nil
	}

	workerCount := s.cfg.Concurrency
	if workerCount > len(ips) {
		workerCount = len(ips)
	}

	type job struct {
		Index int
		IP    string
	}

	jobs := make(chan job, workerCount)
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error

	setErr := func(err error) {
		if err == nil {
			return
		}
		errMu.Lock()
		defer errMu.Unlock()
		if firstErr != nil {
			return
		}
		firstErr = err
		cancel()
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				result := s.scanIP(scanCtx, j.IP)
				results[j.Index] = result

				if result.Passed {
					if err := successWriter.Append(result.Line); err != nil {
						setErr(fmt.Errorf("append success line: %w", err))
						return
					}
					if err := detailWriter.Append(result.CSVLine); err != nil {
						setErr(fmt.Errorf("append success csv line: %w", err))
						return
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for index, ip := range ips {
			select {
			case <-scanCtx.Done():
				return
			case jobs <- job{Index: index, IP: ip}:
			}
		}
	}()

	wg.Wait()
	if firstErr != nil {
		return results, firstErr
	}
	if err := scanCtx.Err(); err != nil && err != context.Canceled {
		return results, err
	}
	return results, nil
}

func (s *Scanner) scanIP(ctx context.Context, ip string) ipScanResult {
	pingResult := s.pinger.Once(ctx, ip)

	probeResults := make([]probeResult, 0, len(s.probes))
	for _, p := range s.probes {
		dnsResult := s.dns.LookupTXT(ctx, ip, p.Query)
		ok := dnsResult.OK && dnscheck.ContainsToken(dnsResult.Records, s.cfg.ExpectedToken)
		probeResults = append(probeResults, probeResult{
			Probe: p,
			DNS:   dnsResult,
			OK:    ok,
		})
	}

	successCount := 0
	patternBuilder := strings.Builder{}
	for _, r := range probeResults {
		if r.OK {
			successCount++
			patternBuilder.WriteByte('1')
		} else {
			patternBuilder.WriteByte('0')
		}
	}

	status := "FAIL"
	if successCount >= s.cfg.MinSuccess {
		status = "OK"
	}

	pingChar := "N"
	if pingResult.OK {
		pingChar = "Y"
	}

	avgDNS := averageDurationMS(probeResults)
	line := ip
	csvLine := detailCSVRow(
		ip,
		pingResult.OK,
		patternBuilder.String(),
		successCount,
		s.cfg.QueryCount,
		pingResult.Duration.Milliseconds(),
		avgDNS,
		status,
		reasonForFailures(probeResults),
	)

	fmt.Printf(
		"[%s] %s  ping=%s (%dms)  txt=%d/%d  probes=%s  avg_dns=%dms\n",
		status,
		ip,
		pingChar,
		pingResult.Duration.Milliseconds(),
		successCount,
		s.cfg.QueryCount,
		patternBuilder.String(),
		avgDNS,
	)

	return ipScanResult{
		Passed:  status == "OK",
		Line:    line,
		CSVLine: csvLine,
	}
}

func averageDurationMS(results []probeResult) int64 {
	if len(results) == 0 {
		return 0
	}

	var sum time.Duration
	for _, r := range results {
		sum += r.DNS.Duration
	}
	return (sum / time.Duration(len(results))).Milliseconds()
}

func reasonForFailures(results []probeResult) string {
	for _, r := range results {
		if r.OK {
			continue
		}
		if r.DNS.Error != "-" {
			return r.DNS.Error
		}
		return "TXT_MISMATCH"
	}
	return "-"
}
