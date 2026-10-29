# Finite scheduled public-data startup pilot

Two independently preregistered scheduled starts at 18:37 UTC on October 30 and 31, 2026, each targeting three 90-second public-data windows at 00:10, 00:14 and 00:18 UTC the following day. Madrid: starts 19:37, captures 01:10/01:14/01:18. Maximum lease 5h50m; standard ubuntu-24.04 job timeout 355 minutes.

Only first schedule attempts are eligible. Start and externally published readiness must precede the fixed cutoff 00:08 UTC. Late runs fail; no manual dispatch, retry or backfill. Exactly three collector calls (at most nine market GETs) per session. Evidence uploads use contents:read and pinned Actions, without stored credentials. Artifacts retained 14 days. No ledger, PAPER, financial accounts or orders.

This release adds a separate package and workflow. The original 31-window plan and workflow remain byte-identical. Successful audits apply only to these two scheduled starts; they cannot establish 24/7 reliability, financial acceptance or profitability. Local simulations are fixtures, never native acquisition. Availability and usable data quality are separate.

Recovery must verify API identities, run creation time, archive digests, READY publication timestamp and log hashes. Use this frozen package to audit offline with the V2 consumer and include runCreatedAtMs from the API in github. Preserve every attempt and partial failure. Remove only these two cron triggers after the last window and update this package manifest in a reviewable GitHub change. The absolute plan independently rejects any later-year invocation.
