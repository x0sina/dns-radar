package probe

import (
	"fmt"
	"strings"
)

const (
	MaxLabelLength          = 63
	MaxDomainLength         = 253
	RequiredMinDomainLength = 152
	base32Alphabet          = "abcdefghijklmnopqrstuvwxyz234567"
)

type Options struct {
	BaseDomain      string
	Count           int
	MinDomainLength int
	MaxDomainLength int
	MixedCase       bool
}

type DomainProbe struct {
	Canonical string
	Query     string
	Length    int
}

func Generate(opts Options) ([]DomainProbe, error) {
	if opts.Count < 1 {
		return nil, fmt.Errorf("probe count must be >= 1")
	}

	baseDomain := normalizeDomain(opts.BaseDomain)
	if baseDomain == "" {
		return nil, fmt.Errorf("base domain is empty")
	}
	if len(baseDomain) > MaxDomainLength {
		return nil, fmt.Errorf("base domain must be <= %d chars", MaxDomainLength)
	}
	if err := validateLabels(baseDomain); err != nil {
		return nil, fmt.Errorf("base domain invalid: %w", err)
	}

	minLength := opts.MinDomainLength
	maxLength := opts.MaxDomainLength

	if minLength < RequiredMinDomainLength {
		return nil, fmt.Errorf("min domain length must be >= %d", RequiredMinDomainLength)
	}
	if maxLength > MaxDomainLength {
		return nil, fmt.Errorf("max domain length must be <= %d", MaxDomainLength)
	}
	if maxLength < minLength {
		return nil, fmt.Errorf("max domain length must be >= min domain length")
	}

	minimumUsableLength := maxInt(minLength, len(baseDomain)+2)
	if minimumUsableLength > maxLength {
		return nil, fmt.Errorf("base domain leaves no space for probe labels under %d chars", maxLength)
	}

	targetLengths := buildTargetLengths(opts.Count, minimumUsableLength, maxLength)
	used := make(map[string]struct{}, opts.Count)

	probes := make([]DomainProbe, 0, opts.Count)
	for idx, targetLength := range targetLengths {
		candidateLength := targetLength
		var canonical string

		for candidateLength <= maxLength {
			prefixLength := candidateLength - len(baseDomain) - 1
			prefix, err := buildPrefix(prefixLength, idx+candidateLength)
			if err != nil {
				return nil, err
			}

			canonical = strings.ToLower(prefix + "." + baseDomain)
			if _, exists := used[canonical]; !exists {
				used[canonical] = struct{}{}
				break
			}
			candidateLength++
		}

		if canonical == "" {
			return nil, fmt.Errorf("failed to generate unique probe domains")
		}
		if err := validateProbeDomain(canonical, minLength, maxLength); err != nil {
			return nil, err
		}

		query := canonical
		if opts.MixedCase {
			query = withMixedCase(canonical, idx)
		}

		probes = append(probes, DomainProbe{
			Canonical: canonical,
			Query:     query,
			Length:    len(canonical),
		})
	}

	return probes, nil
}

func normalizeDomain(domain string) string {
	trimmed := strings.TrimSpace(strings.ToLower(domain))
	return strings.TrimRight(trimmed, ".")
}

func validateProbeDomain(domain string, minLength, maxLength int) error {
	if len(domain) < minLength || len(domain) > maxLength {
		return fmt.Errorf("probe %q must be in [%d, %d] chars", domain, minLength, maxLength)
	}
	if err := validateLabels(domain); err != nil {
		return fmt.Errorf("probe %q invalid: %w", domain, err)
	}
	return nil
}

func validateLabels(domain string) error {
	labels := strings.Split(domain, ".")
	if len(labels) == 0 {
		return fmt.Errorf("domain has no labels")
	}

	for _, label := range labels {
		if len(label) == 0 {
			return fmt.Errorf("domain contains empty label")
		}
		if len(label) > MaxLabelLength {
			return fmt.Errorf("label %q exceeds %d characters", label, MaxLabelLength)
		}
	}

	return nil
}

func buildTargetLengths(count, minLength, maxLength int) []int {
	if count == 1 {
		return []int{maxLength}
	}

	lengths := make([]int, 0, count)
	for i := 0; i < count; i++ {
		ratio := float64(i) / float64(count-1)
		length := minLength + int(float64(maxLength-minLength)*ratio+0.5)
		lengths = append(lengths, length)
	}

	return lengths
}

func buildPrefix(totalLength, seed int) (string, error) {
	minLabels := maxInt(1, ceilDiv(totalLength+1, 64))
	maxLabels := (totalLength + 1) / 2
	if minLabels > maxLabels {
		return "", fmt.Errorf("cannot split prefix length %d into DNS labels", totalLength)
	}

	labelCount := minLabels
	charBudget := totalLength - (labelCount - 1)
	if charBudget < labelCount || charBudget > labelCount*MaxLabelLength {
		return "", fmt.Errorf("invalid prefix budget %d for %d labels", charBudget, labelCount)
	}

	lengths := make([]int, labelCount)
	for i := range lengths {
		lengths[i] = 1
	}

	remaining := charBudget - labelCount
	for i := 0; i < labelCount && remaining > 0; i++ {
		add := minInt(MaxLabelLength-1, remaining)
		lengths[i] += add
		remaining -= add
	}

	if remaining != 0 {
		return "", fmt.Errorf("prefix accounting failed for %d", totalLength)
	}

	labels := make([]string, 0, labelCount)
	for i, length := range lengths {
		labels = append(labels, makeLabel(length, seed, i))
	}

	return strings.Join(labels, "."), nil
}

func makeLabel(length, seed, labelIndex int) string {
	label := make([]byte, length)
	base := (seed*19 + labelIndex*23) % len(base32Alphabet)
	for i := 0; i < length; i++ {
		idx := (base + i*7 + seed) % len(base32Alphabet)
		label[i] = base32Alphabet[idx]
	}
	return string(label)
}

func withMixedCase(domain string, seed int) string {
	bytes := []byte(domain)
	letterPos := 0

	for i, ch := range bytes {
		if ch < 'a' || ch > 'z' {
			continue
		}

		if (letterPos+seed)%2 == 0 {
			bytes[i] = ch - ('a' - 'A')
		}
		letterPos++
	}

	return string(bytes)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func ceilDiv(a, b int) int {
	return (a + b - 1) / b
}
