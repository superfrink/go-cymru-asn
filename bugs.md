# Bugs and Issues (Prioritized)

All bugs have been fixed on branch `fix-p0-bugs`.

## P0 — Critical ✅

| # | Issue | Status | Commit |
|---|-------|--------|--------|
| 1 | **Unbounded `io.ReadAll`** — malicious/buggy server can exhaust memory | ✅ Fixed | d6165ce |
| 2 | **No deadline if context has no deadline** — `context.Background()` causes reads to hang forever | ✅ Fixed | d6165ce |

## P1 — High ✅

| # | Issue | Status | Commit |
|---|-------|--------|--------|
| 3 | **IP normalization mismatch** — `matchResultsToIPs` does string comparison but Cymru may normalize IPs differently | ✅ Fixed | 5b8ed4e |
| 4 | **Silent parse errors** — malformed lines are silently skipped | ✅ Fixed | 7fef176 |

## P2 — Medium ✅

| # | Issue | Status | Commit |
|---|-------|--------|--------|
| 5 | **64KB line limit** — `bufio.Scanner` default token limit can fail on long lines | ✅ Fixed | 271671b |
| 6 | **Short writes not handled** — `conn.Write(request)` can return short | ✅ Fixed | d7e431d |

## P3 — Low ✅

| # | Issue | Status | Commit |
|---|-------|--------|--------|
| 7 | **Deferred close error ignored** — `err` isn't a named return | ✅ Fixed | d6165ce |
| 8 | **Stdin scanner ignores `scanner.Err()`** — read errors silently discarded | ✅ Fixed | 1df3064 |
| 9 | **`ErrNoResults` defined but never used** | ✅ Fixed | 63ca42c |

## Enhancements

| Feature | Commit |
|---------|--------|
| OpenBSD pledge/unveil sandbox support | 752845d |
