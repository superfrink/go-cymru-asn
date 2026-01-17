# Bugs and Issues (Prioritized)

## P0 — Critical

| # | Issue | Location | Why |
|---|-------|----------|-----|
| 1 | **Unbounded `io.ReadAll`** — malicious/buggy server can exhaust memory | client.go#L135 | DoS vector; can crash production systems |
| 2 | **No deadline if context has no deadline** — `context.Background()` causes reads to hang forever | client.go#L124-L128 | Hangs indefinitely; common usage pattern in CLI |

## P1 — High

| # | Issue | Location | Why |
|---|-------|----------|-----|
| 3 | **IP normalization mismatch** — `matchResultsToIPs` does string comparison but Cymru may normalize IPs differently (IPv6 compression, etc.) | client.go#L144-L160 | Causes false "no result" errors for valid lookups |
| 4 | **Silent parse errors** — malformed lines are silently skipped | parser.go#L46-L49 | Hides upstream format changes; debugging nightmare |

## P2 — Medium

| # | Issue | Location | Why |
|---|-------|----------|-----|
| 5 | **64KB line limit** — `bufio.Scanner` default token limit can fail on long lines | parser.go#L29, main.go#L71 | Can fail on legitimate long AS names |
| 6 | **Short writes not handled** — `conn.Write(request)` can return short | client.go#L130 | Rare but causes silent data corruption |

## P3 — Low

| # | Issue | Location | Why |
|---|-------|----------|-----|
| 7 | **Deferred close error ignored** — `err` isn't a named return | client.go#L117-L122 | Close errors rarely actionable |
| 8 | **Stdin scanner ignores `scanner.Err()`** — read errors silently discarded | main.go#L71-L77 | Edge case; stdin errors rare |
| 9 | **`ErrNoResults` defined but never used** | parser.go#L14 | Dead code; no runtime impact |

## Recommended Fix Order

1. Wrap `conn` with `io.LimitReader` before `ReadAll` (P0)
2. Always set a deadline based on `c.timeout` even when ctx has none (P0)
3. Canonicalize IPs via `net.ParseIP(ip).String()` before storing/comparing (P1)
4. Track/expose parse errors instead of silently dropping lines (P1)
5. Increase scanner buffer or switch to `bufio.Reader` (P2)
6. Handle short writes or use `io.Copy(conn, bytes.NewReader(request))` (P2)
