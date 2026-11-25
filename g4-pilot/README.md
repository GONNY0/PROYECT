# Finite public availability pilot

This separate, preregistered pilot tests three public-data captures within one already-running standard GitHub-hosted Linux job. Registration: 2026-10-28T14:06:41.640Z. Exact plan SHA256: 409bc5880c2ac4fdb207da6e6d596c5cea74c245664dd50dac1fec819aa4c481.

- pilot-20261028-01: 2026-10-28T14:19:00.000Z to 2026-10-28T14:20:30.000Z
- pilot-20261028-02: 2026-10-28T14:23:00.000Z to 2026-10-28T14:24:30.000Z
- pilot-20261028-03: 2026-10-28T14:27:00.000Z to 2026-10-28T14:28:30.000Z

The job must prepare and upload READY before the first opening, then start its supervisor before that opening. Each envelope preserves original public response bytes. Late starts, missed windows, termination failures and partial artifacts remain failures. No retry or backfill is authorized. Maximum nine public market GETs and thirty minutes from registration. No cron, paid runner, cache, account credentials or orders. Artifacts retained for seven days.

Run node verify-package.mjs and node --test work/tests/*availability-pilot.test.mjs from this directory. The workflow runs all six public test files before preparing. The local recovery verifies each ZIP against its GitHub API digest and binds READY, summary and per-window result hashes to the corresponding run log. The Windows inspector validates the READY ZIP without executing archive code.

This does not establish daily autonomous startup, 24/7 operation, independent UTC accuracy or cryptographic provider attestation. It contributes nothing to the original 31-window calendar, financial V1/V2 or PAPER. Availability and usable quality are counted separately; a future financial decision requires new data and Risk Core. No financial acceptance or profitability is claimed.
