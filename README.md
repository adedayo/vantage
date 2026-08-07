[![License](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](LICENSE)
[![golangci-lint](https://github.com/adedayo/vantage/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/adedayo/vantage/actions/workflows/golangci-lint.yml)
[![build](https://github.com/adedayo/vantage/actions/workflows/build.yml/badge.svg)](https://github.com/adedayo/vantage/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/tag/adedayo/vantage?label=release)](https://github.com/adedayo/vantage/releases)

# Vantage

**See what an attacker sees.** `vantage` audits the attack surface an
organisation exposes, from the vantage point of someone looking at it — no
agents, no credentials, and nothing touching the systems being assessed.

Reconnaissance starts with DNS, because DNS answers everybody. Before an
attacker sends a single packet at you, it tells them which hosts you expose,
whose infrastructure they sit on, whether mail claiming to be from you can be
forged, whether your delegation can be tampered with, and which names your
certificates have already made public. `vantage` asks the same questions
first, and reports what an attacker would find, ranked by what it would cost
you.

Today every assessment is made from the **external** vantage: the public
internet, with no privileged position. That is what `--from external`, the
default, means. Internal vantages — what is exposed to someone who has already
reached an internal network — are the direction of travel, not a current
capability.

It grades a domain A–F, explains every finding with the evidence behind it and
the remediation that closes it, and emits JSON, NDJSON, CSV or SARIF for a
pipeline.

It runs on **Linux, macOS and Windows** — resolver configuration is discovered in
a platform-native way with graceful fallbacks, so no `/etc/resolv.conf` is
required.

> Some checks reach beyond DNS to corroborate what DNS implies: Certificate
> Transparency logs, cloud provider range data, and the HTTPS policy files that
> MTA-STS and subdomain takeover checks depend on. All of it is public, and
> every check declares its egress — see [Network egress](#network-egress).

## Install

**macOS and Linux — Homebrew**

```sh
brew install adedayo/tap/vantage
```

Upgrade with `brew upgrade vantage`.

**Windows — winget**

```powershell
winget install adedayo.vantage
```

**Linux — distribution packages**

`.deb`, `.rpm`, `.apk` and Arch packages are attached to every release, so the
binary is installed and removed by your package manager rather than left on
`PATH` by hand. Substitute the version and your architecture (`amd64` or
`arm64`):

```sh
VERSION=1.1.0
ARCH=amd64
BASE="https://github.com/adedayo/vantage/releases/download/v${VERSION}"

# Debian, Ubuntu
curl -fsSLO "${BASE}/vantage_${VERSION}_linux_${ARCH}.deb"
sudo dpkg -i "vantage_${VERSION}_linux_${ARCH}.deb"

# Fedora, RHEL, openSUSE
sudo rpm -i "vantage_${VERSION}_linux_${ARCH}.rpm"

# Alpine
sudo apk add --allow-untrusted "vantage_${VERSION}_linux_${ARCH}.apk"

# Arch
sudo pacman -U "vantage_${VERSION}_linux_${ARCH}.pkg.tar.zst"
```

**Docker**

```sh
docker run --rm ghcr.io/adedayo/vantage:latest audit example.com
```

The image is `distroless`, so it has no shell — `docker run ... sh` will not
work, by design. Provider ranges and Certificate Transparency results are
cached inside the container and lost when it exits; mount a volume to keep
them between runs:

```sh
docker run --rm -v vantage-cache:/home/nonroot/.cache/vantage \
  ghcr.io/adedayo/vantage:latest audit example.com
```

Images are published for `linux/amd64` and `linux/arm64`. Tags are `latest`,
the version (`1.1.0`) and the tag (`v1.1.0`).

**Direct download**

Binaries for every platform, with signed checksums and an SBOM, are on the
[latest release](https://github.com/adedayo/vantage/releases/latest).

```sh
# Pick the archive matching your platform, e.g. darwin_arm64, linux_amd64.
VERSION=1.1.0
PLATFORM=darwin_arm64

curl -fsSLO "https://github.com/adedayo/vantage/releases/download/v${VERSION}/vantage_${VERSION}_${PLATFORM}.tar.gz"
curl -fsSLO "https://github.com/adedayo/vantage/releases/download/v${VERSION}/vantage_${VERSION}_checksums.txt"

# Verify before running it. A security tool that arrives unverified is a
# contradiction.
shasum -a 256 -c vantage_${VERSION}_checksums.txt --ignore-missing

tar -xzf "vantage_${VERSION}_${PLATFORM}.tar.gz"
sudo mv vantage /usr/local/bin/
vantage version
```

On macOS the binary is not notarised, so Gatekeeper will quarantine a download
made through a browser. Fetching it with `curl` as above avoids that; otherwise
clear the attribute with `xattr -d com.apple.quarantine vantage`. The Homebrew
cask does this for you.

On Windows, download `vantage_<version>_windows_amd64.zip` (or `windows_arm64`),
extract it and put `vantage.exe` somewhere on your `PATH`.

**With Go**

If you already have a Go toolchain, `go install` builds from source and needs no
release archive:

```sh
go install github.com/adedayo/vantage@latest
```

This puts `vantage` in `$(go env GOPATH)/bin`, which needs to be on your `PATH`.
Use `@v1.1.0` in place of `@latest` to pin a version.

> Installing the command is not the same as depending on the Go packages. See
> [Compatibility](#compatibility) — the CLI is the supported surface; `pkg/` is
> an implementation detail.

## Commands

| Command | Description |
|---|---|
| `spf <domain>` | Sender Policy Framework record |
| `dkim <domain> -s <selector>` | DKIM public key record |
| `dmarc <domain>` | Effective DMARC policy |
| `dmarc-report <domain>` | DMARC policy plus `rua`/`ruf` reporting URIs |
| `mtasts <domain>` | MTA-STS TXT record, plus the policy file when findings are requested (`--no-network` to skip) |
| `tlsrpt <domain>` | SMTP TLS Reporting (`_smtp._tls`) record |
| `bimi <domain>` | Brand Indicators for Message Identification (`default._bimi`) |
| `dnssec <domain>` | DNSSEC chain of trust: DNSKEY, parent DS, algorithms, signature expiry and denial of existence |
| `nssec <domain>` | NSEC/NSEC3 denial-of-existence records |
| `smtp-dane <domain>` | TLSA records at `_25._tcp` |
| `https-dane <domain>` | TLSA records at `_443._tcp` |
| `ssh-dane <domain>` | TLSA records at `_22._tcp` |
| `caa <domain>` | Certification Authority Authorization records, climbing the domain tree per RFC 8659 |
| `ptr <domain>` | Reverse DNS lookup |
| `dnsbl <domain> -b <zone>` | DNS blocklist reputation check |
| `public-suffix <domain>` | Public Suffix List validation |
| `catalogue` | List every finding vantage can report |
| `explain <finding-id>` | Explain a finding and how to fix it |
| `version` | Version, commit, build date and platform (also `--version`) |

## Vantage points

An assessment is made *from* somewhere, and what is exposed depends on where
the observer stands. `vantage audit --from` names that position:

```sh
vantage audit example.com --from external   # the default
```

| Vantage | Meaning | Status |
|---|---|---|
| `external` | The public internet, with no privileged position and no credentials | Implemented |
| `internal` | What is exposed to someone who has already reached an internal network | Not yet implemented |

`internal` is recognised but rejected, so asking for it tells you the
capability is absent rather than that you mistyped. It is not listed in
`--help`, because advertising a value that cannot run would be a false
promise.

## Findings and reporting

By default a command retrieves and prints the record. Pass `--findings` — or any
structured output format — to assess it instead:

```sh
vantage spf example.com                    # v=spf1 include:_spf.example.com ~all
vantage spf example.com --findings         # prioritised findings with remediation
vantage dmarc example.com -o json          # full result envelope
```

Findings carry a stable identifier, a severity, the evidence behind the
conclusion and reviewed remediation guidance:

```
LOW       SURF-SPF-005  SPF record uses softfail (~all) rather than fail (-all)
          The record terminates in `~all`. Mail from unauthorised hosts is
          marked but generally still delivered...
          Evidence: example.com TXT = v=spf1 include:_spf.example.com ~all
          Fix: Once DMARC aggregate reports confirm all legitimate senders are
          covered, tighten the terminal mechanism to `-all`.
```

Look any identifier up without running an assessment:

```sh
vantage catalogue --check spf
vantage explain SURF-SPF-004
```

### Output formats

| Flag | Purpose |
|---|---|
| `-o text` | Human-readable (default) |
| `-o json` | Complete result envelope |
| `-o ndjson` | One object per line; streams, and stays cheap in bulk |
| `-o csv` | Flattened findings |
| `-o sarif` | SARIF 2.1.0 for GitHub code scanning and similar |

| Flag | Purpose |
|---|---|
| `--severity <level>` | Only report findings at or above this level |
| `--fail-on <level>` | Exit 3 if anything reaches this level |
| `--fields a,b,c` | Restrict structured output to these fields |
| `--summary` | Counts and check states only |
| `--no-catalogue-text` | Omit prose; resolve it later with `explain` |

### Exit codes

Exit codes are a contract, so a caller never has to parse output to learn what
happened — and a resolver outage is never mistaken for a security finding:

| Code | Meaning |
|---|---|
| 0 | Completed; nothing met the `--fail-on` threshold |
| 1 | Runtime error — the tool could not do its job |
| 2 | Usage error — bad flag or missing argument |
| 3 | Completed; a finding met or exceeded `--fail-on` |
| 4 | Completed, but one or more checks failed (partial result) |

```sh
vantage spf example.com --fail-on high -o sarif > results.sarif
```

### Absent versus unassessed

Structured output distinguishes `ok`, `not_found`, `not_checked` and
`check_failed`. "No record published" and "we could not tell" are different
statements, and conflating them would let a reader conclude a control is missing
when in truth it was never assessed.

## Network egress

Almost everything `vantage` does is DNS. One check goes further: **MTA-STS
retrieves the policy file** over HTTPS from
`https://mta-sts.<domain>/.well-known/mta-sts.txt`, because the TXT record alone
proves nothing. A domain advertising a policy it does not actually serve has the
appearance of protection without the substance, and senders have nothing to
enforce.

That request is made to the target's own infrastructure, never to a third party.
Redirects are refused and the certificate is validated, both required by
RFC 8461 §3.2 — following a redirect would let whoever controls the hop rewrite
the policy being audited.

`--no-network` restricts a run to DNS. It does **not** silently drop MTA-STS:
the check still runs and still reports a missing policy, since that is visible
from the TXT record alone and is the most consequential finding. Only the
policy-dependent rules are skipped, and the retrieved policy is absent from the
evidence so the report never implies a document was inspected when it was not.

```sh
vantage audit example.com --no-network   # DNS only
vantage mtasts example.com --no-network  # TXT record only
```

Checks declare their egress, so `vantage audit --list-checks` shows the blast
radius before you invoke anything.

### Third-party services

Two checks consult services that are neither yours nor the target's, and both
say so in the report:

- **`net`** attributes each address in the estate to a hosting provider, using
  the published address ranges of AWS, Google Cloud, Cloudflare and Fastly. It
  reports addresses that should never appear in public DNS — RFC 1918 space,
  link-local, documentation ranges and the rest of the IANA special-purpose
  registry — because publishing one discloses internal addressing to anyone who
  asks. Azure is not covered: its published range file is versioned by a URL
  that rotates weekly, so attribution would silently stop working whenever
  Microsoft moved it. Azure-hosted addresses are reported as unattributed
  rather than guessed at.

- **`ct`** enumerates hostnames from Certificate Transparency logs via
  Cert Spotter, falling back to crt.sh. Every name a certificate has ever been
  issued for is already public; the check reads that record and asks which of
  those names still resolve. It is **opt-in** — pass `--enumerate` — because it
  queries a third party and because the answer is an inventory rather than a
  verdict.

```sh
vantage audit example.com --enumerate
vantage audit example.com --checks net --expect-jurisdiction GB,IE
```

`--expect-jurisdiction` names the countries you expect to be hosted in; anything
outside them is reported. Jurisdiction is inferred from the provider's own
region naming, which is an approximation of where data sits, not a legal
determination.

Names discovered by `ct` are fed to the other checks before they run, so a
hostname found in a log is assessed for takeover and attribution like one you
supplied yourself. Enumeration failing is never fatal: the run continues with
the names you gave it.

### Pivoting to related domains

`--enumerate` stays inside the zone you named. `--pivot` goes further: a
registrable domain that appears on the same certificate as your target is
treated as a target in its own right and assessed in full. Certificates are
issued to whoever proves control of every name on them, so co-tenancy on a small
certificate is decent evidence that one organisation holds both.

```sh
vantage audit example.com --pivot
```

Discovered domains are reported as `SURF-CT-004`, at informational severity. The
inference is not proof — shared hosting can bundle unrelated customers onto one
certificate — so relations are only drawn from certificates small enough for
co-tenancy to mean something, and the walk is bounded:

| Flag | Purpose |
|---|---|
| `--pivot-depth` | Hops of co-tenancy to follow |
| `--pivot-budget` | Ceiling on domains enumerated, including the ones you supplied |
| `--pivot-max-sans` | Largest certificate, by name count, from which a relation is inferred |

Raising `--pivot-max-sans` finds more relations and admits more neighbours who
merely shared a certificate. **Only pivot against domains you are authorised to
assess** — the flag will happily walk into estates that are not yours, and the
tool cannot tell the difference.

### Caches

Provider ranges and CT results are cached under `~/.cache/vantage`
(`~/Library/Caches/vantage` on macOS):

| Data | Location | Lifetime |
|---|---|---|
| Provider address ranges | `netattr/` | 7 days |
| Certificate Transparency results | `ct/` | 24 hours |

If a source is unreachable and a stale entry exists, the stale entry is used and
the report says when it was fetched — an old answer that discloses its age is
more use than no answer at all. Delete the directory to force a refresh.

Where an operator publishes more than one equivalent endpoint, each is tried in
turn, so a single URL being withdrawn does not remove that provider's coverage.
Attribution results carry a `provenance:` record naming the endpoint used and
the date the data was obtained, because an attribution can change when this
tool's data is refreshed rather than when the domain changes — a distinction
that matters when comparing two runs.

## Authority to assess

`vantage` is an assessment tool, not an exploitation tool. It observes; it
never claims a resource, guesses a credential or attempts to take anything over.
Some checks nonetheless query the target's own nameservers directly rather than
going through a resolver:

- **`wild`** asks for three random, never-registered names, to establish
  whether the zone answers for everything.
- **`ns`** asks each authoritative server for the zone's SOA, to see which of
  them answer authoritatively and whether they agree; and asks each one to
  resolve a foreign name, to see whether it is an open resolver.
- **`tko`** follows the alias chain of each host you name and checks whether
  its target still exists. It never claims a resource, and it never guesses
  hostnames — it assesses the apex plus whatever you supply:

```sh
vantage audit example.com --checks tko --hosts www.example.com,assets.example.com
vantage audit example.com --checks tko --hosts-file hosts.txt
```

- **`axfr`** asks each authoritative server for a zone transfer. A correctly
  configured server refuses, which is the answer being tested for. The
  transferred zone is never written to disk and never appears in the report:
  a finding records the record count and a five-record sample, enough to prove
  the disclosure without republishing it. Because it is more intrusive than an
  ordinary query, `axfr` is in the `surface` and `deep` profiles only, never in
  the default.

If no server answers at all, the check reports **`check_failed`**, not a clean
result: a zone that could not be tested is never reported as one that passed.
That happens more often than you might expect — some nameservers accept the TCP
connection and answer ordinary queries but silently drop AXFR, and outbound
TCP/53 is filtered on many corporate networks. The report lists every server
tried and what each one said, so you can tell the difference.

Each of these can be skipped individually with
`--skip-checks wild,ns,tko,axfr`.

**You are responsible for having authority to assess the domains you target.**
Auditing a domain you neither own nor have written permission to test may be
unlawful in your jurisdiction regardless of how gentle the queries are.

## Choosing resolvers

By default `vantage` discovers nameservers in this order:

1. The `--resolver` flag (repeatable).
2. The `VANTAGE_RESOLVERS` environment variable (comma-separated).
3. Platform-native configuration:
   - Linux / macOS / BSD: `/etc/resolv.conf`
   - Windows: `GetAdaptersAddresses` (IP Helper API)
4. Well-known public resolvers (Cloudflare, Google, Quad9).

Addresses may be given with or without a port; `53` is assumed.

```sh
vantage caa example.com --resolver 1.1.1.1
vantage spf example.com --resolver 8.8.8.8 --resolver 9.9.9.9
VANTAGE_RESOLVERS=1.1.1.1,8.8.8.8 vantage dmarc example.com
```

Resolvers are tried in order, so one unreachable nameserver does not fail the
audit. Truncated UDP responses are automatically retried over TCP.

## Timeouts

Two budgets bound every lookup. The defaults favour **fast failover** — a dead
nameserver is abandoned after 2 seconds rather than stalling the audit.

| Budget | Scope | Default | Flag | Environment variable |
|---|---|---|---|---|
| Query | One attempt against one resolver | `2s` | `--query-timeout` | `VANTAGE_QUERY_TIMEOUT` |
| Total | The whole lookup, across all resolvers | `10s` | `--timeout` | `VANTAGE_TIMEOUT` |

If you are on a slow, lossy or high-latency link (satellite, VPN, Tor, filtered
networks) and want the tool to wait longer, raise either or both:

```sh
# Be more patient with each resolver
vantage spf example.com --query-timeout 5s --timeout 30s

# Same, via the environment
VANTAGE_QUERY_TIMEOUT=5s VANTAGE_TIMEOUT=30s vantage spf example.com

# Or fail over even faster on a flaky network
vantage spf example.com --query-timeout 500ms
```

Precedence is flag → environment variable → default. A single attempt never
overruns the total budget, and a `context.Context` deadline shorter than the
total timeout always wins.

## Library

`vantage` is a library first and a command second. The `vantage` binary is an
ordinary consumer of the same interface an embedding tool uses — it holds no
private hooks — so anything the CLI can do, your code can do.

The entry point is `audit.Assessor`: ask what the library can assess, then ask
it to assess some of that.

```go
ctx := context.Background()

resolver := vantage.NewClient(vantage.ConfigFromEnv())

assessor, err := audit.NewAssessor(resolver, audit.WithVersion("myapp/1.4.0"))
if err != nil {
	return err
}

result, err := assessor.Assess(ctx, audit.Request{
	Targets:   []string{"example.com"},
	Selection: audit.Selection{Profile: audit.ProfileStandard},
})
```

The resolver is a required argument, not an option, and there is no
package-level default. An assessor that could invent its own egress would
defeat any scope guard wrapped around it, silently, at the moment it mattered
most. Nothing configurable lives in package state, so two assessments under
different authorisations can run concurrently in one process.

Two things catch most consumers out:

- **A nil error does not mean everything succeeded.** It means the run
  completed. A check that fails is recorded and the others continue; inspect
  `result.Checks` and `result.Errors`.
- **There are four check states, and they do not reduce to two.** `not_found`
  is a measurement; `check_failed` is the absence of one. Collapsing them
  reports an unmeasured control as a passing one.

**[Read the embedding guide](docs/embedding.md)** for the full contract:
scope-guarded transports, structured progress, building your finding mapping
against `Catalogue` rather than a hard-coded list, sharing downloaded provider
ranges, and reviewing declared egress before a run.

All functions take a `context.Context` as their first argument and return errors
prefixed with `error:`, wrapping the sentinels in `pkg` (see the table in spec
`002`). Match with `errors.Is`, and switch on `finding.CheckError.Code` rather
than parsing messages.

## Compatibility

Version numbers describe the **command-line interface and the embedding API**,
because those are what people depend on and what is expensive to break. Within
a major version:

| Stable | Meaning |
|---|---|
| Exit codes | 0–4 keep their meanings; a script gating on them keeps working |
| Finding identifiers | `SURF-SPF-004` always denotes the same condition. Rules may be added, and the prose or severity of an existing rule may be revised, but an identifier is never reused for a different condition |
| Structured output | Fields are added, not removed or repurposed; `schema_version` carries the contract |
| Command and flag names | Existing invocations keep working; flags may be added |
| Embedding API | `audit.Assessor`, `Request`, `Capabilities`, `Progress`, the `Option` constructors, the `finding` types and the `pkg` sentinels. Fields are added, not removed or repurposed |

**The rest of `pkg/` is not covered.** Individual scanners, the analysis
internals and the check implementations change whenever the work needs them to,
including in patch releases. Reach them through `audit.Assessor` and you are on
the supported path; import them directly and you should pin a commit.

That split is the trade. Freezing every exported symbol would slow the work that
makes the tool useful; freezing the surface an embedder actually needs — which
is small, and was designed to be — costs little and protects the people building
on it. New finding identifiers may appear in a minor release, which is why a
consumer's mapping should be derived from `Catalogue` and validated in CI rather
than maintained by hand.

## Specifications

Specifications live under [`openspec/changes/`](openspec/changes). See
[`openspec/ROADMAP.md`](openspec/ROADMAP.md) for sequencing.

## Development

```sh
go test ./... -cover
go vet ./...
GOOS=windows go build ./...
```

### Pre-release verification

`pre-release.sh` runs the full local quality gate — module tidiness, `gofmt`,
`go vet`, `golangci-lint`, tests with the race detector and coverage,
cross-platform builds for Linux/macOS/Windows (amd64 and arm64), and an offline
CLI smoke test:

```sh
./pre-release.sh
```

| Variable | Effect |
|---|---|
| `SKIP_LINT=1` | Skip golangci-lint (not recommended) |
| `SKIP_RACE=1` | Skip the race detector |
| `AUTO_INSTALL=1` | Install golangci-lint if missing |
| `MIN_COVERAGE=40` | Fail if total coverage drops below the given percentage |

golangci-lint is configured in [`.golangci.yml`](.golangci.yml); install it with
`brew install golangci-lint` or:

```sh
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
```

[GoReleaser](https://goreleaser.com) is optional but recommended — `pre-release.sh`
validates [`.goreleaser.yml`](.goreleaser.yml) when it is on `PATH`:

```sh
go install github.com/goreleaser/goreleaser/v2@latest
```

### Releasing

`release.sh` runs `pre-release.sh` first and **only** commits, tags and pushes if
every check passes.

```sh
./release.sh patch      # bump the patch component of the latest tag
./release.sh minor
./release.sh major
./release.sh v1.2.3     # or name the version explicitly

DRY_RUN=1 ./release.sh patch    # show what would happen, change nothing
```

It refuses to run if the tag already exists locally or on the remote, and if the
working tree is dirty (unless `ALLOW_DIRTY=1`, which folds the changes into the
release commit). The tag is annotated with the commit subjects since the previous
release, and publication is handled by `goreleaser`, then `gh`, then CI —
whichever is available first.

Pushing a `vX.Y.Z` tag triggers
[`.github/workflows/release.yml`](.github/workflows/release.yml), which runs the
test suite and then GoReleaser. Each release ships:

- Prebuilt, statically linked binaries for linux, darwin and windows on both
  `amd64` and `arm64` (`tar.gz`, or `zip` on Windows).
- A `checksums.txt` file with SHA-256 digests of every archive.
- An SBOM per archive, generated with [syft](https://github.com/anchore/syft).
- Version, commit and build date baked into the binary — check with
  `vantage version`.

Local `goreleaser` runs skip SBOM generation automatically when syft is not
installed.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
