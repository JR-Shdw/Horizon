// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//
// Goes to providers/v1/rhorizon/util.go in external-secrets/external-secrets.
//
// Tiny helpers split out of client.go to keep that file readable.

package rhorizon

import (
	"context"
	"regexp"
	"sync"
	"time"
)

// regexCache memoises compiled regexes, ESO calls GetAllSecrets per
// reconciliation, so the same Name.RegExp gets compiled repeatedly
// without this.
var (
	regexCache   = map[string]*regexp.Regexp{}
	regexCacheMu sync.Mutex
)

func regexpMatch(pattern, value string) (bool, error) {
	regexCacheMu.Lock()
	re, ok := regexCache[pattern]
	if !ok {
		var err error
		re, err = regexp.Compile(pattern)
		if err != nil {
			regexCacheMu.Unlock()
			return false, err
		}
		regexCache[pattern] = re
	}
	regexCacheMu.Unlock()
	return re.MatchString(value), nil
}

// contextWithTimeout is a tiny helper used by Validate to bound the
// liveness probe.
func contextWithTimeout(seconds int) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
}
