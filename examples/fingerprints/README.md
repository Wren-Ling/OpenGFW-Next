# Local JA3/JA4 fingerprint datasets

These files are intentionally empty. Populate them only with fingerprints you
captured from clients and servers you control, then validated against normal VM
traffic in your environment.

Do not copy public placeholder hashes or random hashes from issue trackers into
production. JA3 and JA4 vary by TLS/QUIC library, client version, uTLS profile,
operating system, and evasion settings; stale or unvalidated values create noisy
false positives.

Each file can be a top-level `suspicious` list:

```yaml
suspicious:
  - hash: "replace-with-local-capture"
    name: "mihomo-1.18.8-utls-chrome-lab"
    severity: medium
    tags: ["mihomo", "lab"]
```

A bare YAML list of entries is also accepted.
