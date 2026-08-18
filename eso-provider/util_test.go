// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//
// Goes to providers/v1/rhorizon/util_test.go in external-secrets/external-secrets.
//
// Tests pour regexpMatch (cache + concurrent safety) et contextWithTimeout.

package rhorizon

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRegexpMatch_HitsAndMisses(t *testing.T) {
	cases := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"^prod/", "prod/db", true},
		{"^prod/", "dev/db", false},
		{`\d+`, "abc123", true},
		{`\d+`, "abcdef", false},
		{"", "anything", true}, // empty regex matches everything per Go RE2
	}
	for _, c := range cases {
		got, err := regexpMatch(c.pattern, c.value)
		if err != nil {
			t.Errorf("regexpMatch(%q, %q) err: %v", c.pattern, c.value, err)
			continue
		}
		if got != c.want {
			t.Errorf("regexpMatch(%q, %q) = %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
}

func TestRegexpMatch_BadPatternReportsError(t *testing.T) {
	// Unbalanced bracket → compile error.
	ok, err := regexpMatch("[unclosed", "irrelevant")
	if err == nil {
		t.Fatalf("expected compile error on invalid regex")
	}
	if ok {
		t.Errorf("expected ok=false on error, got true")
	}
	if !strings.Contains(err.Error(), "missing closing") &&
		!strings.Contains(err.Error(), "error parsing") {
		t.Logf("err format may have drifted (Go std lib changes): %v", err)
	}
}

func TestRegexpMatch_CacheReuses(t *testing.T) {
	// First call populates the cache ; subsequent calls must reuse the
	// same *regexp.Regexp pointer instead of compiling again.
	const pat = "^cache-test-[0-9]+$"
	if _, err := regexpMatch(pat, "cache-test-1"); err != nil {
		t.Fatalf("first call err: %v", err)
	}
	regexCacheMu.Lock()
	firstPtr := regexCache[pat]
	regexCacheMu.Unlock()
	if firstPtr == nil {
		t.Fatalf("pattern not cached after first compile")
	}

	if _, err := regexpMatch(pat, "cache-test-2"); err != nil {
		t.Fatalf("second call err: %v", err)
	}
	regexCacheMu.Lock()
	secondPtr := regexCache[pat]
	regexCacheMu.Unlock()
	if firstPtr != secondPtr {
		t.Errorf("cache miss : pattern recompiled instead of reused")
	}
}

func TestRegexpMatch_ConcurrentSafe(t *testing.T) {
	// ESO's reconcile loop calls GetAllSecrets concurrently across N
	// ExternalSecrets. The cache mutex must serialize, no panics, no
	// races detected by `go test -race`.
	const pat = "^race-[a-z]+$"
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _ = regexpMatch(pat, "race-abc")
			}
		}()
	}
	wg.Wait()
}

func TestContextWithTimeout_RespectsDeadline(t *testing.T) {
	ctx, cancel := contextWithTimeout(1)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatalf("context has no deadline")
	}
	delta := time.Until(deadline)
	// Allow generous wiggle ; the assertion is about presence of a
	// 1s-ish deadline, not exact wall-clock precision.
	if delta < 500*time.Millisecond || delta > 1500*time.Millisecond {
		t.Errorf("deadline drift: ~1s expected, got %v", delta)
	}
}

func TestContextWithTimeout_CancelInvokes(t *testing.T) {
	ctx, cancel := contextWithTimeout(60)
	cancel()
	// After cancel, the ctx must be Done immediately.
	select {
	case <-ctx.Done():
		// expected
	default:
		t.Errorf("context not Done after cancel")
	}
	if err := ctx.Err(); err == nil {
		t.Errorf("ctx.Err() nil after cancel")
	} else if err != context.Canceled {
		t.Errorf("ctx.Err() = %v, want context.Canceled", err)
	}
}
