package scanner

import (
	"dns-radar/internal/dnscheck"
	"dns-radar/internal/probe"
)

type probeResult struct {
	Probe probe.DomainProbe
	DNS   dnscheck.Result
	OK    bool
}

type ipScanResult struct {
	Passed  bool
	Line    string
	CSVLine []string
}
