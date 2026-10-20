# G4 public capture portability

This isolated package verifies public market-data acquisition on Linux and offline
replay on another host. It contains no account records, credentials, private
database, trading adapter, order submission entry point, or project Git history.
The shared HTTP transport is reused only in DATA mode by the entry point.

The workflow is a one-shot verification on pushes to its dedicated branch.
It is not an always-on service or a financial experiment. No daily coverage,
execution quality, fills, returns, or financial-account acceptance are established.
Incomplete acquisitions remain incomplete; no missing observations are backfilled.

Standard GitHub-hosted Linux runners in this public repository are used.
No paid runners, models, account credentials, services or billing settings are configured.
Source and provider-response hashes are local integrity evidence, not provider signatures.
Artifacts expire after seven days and must be downloaded for durable local evidence.
