# G4 bounded public availability probe

The immutable plan has 31 UTC windows, 00:10 inclusive to 00:20 exclusive,
from 2026-10-21 through 2026-11-20. The timer requests a run at 00:13.
GitHub can delay or drop scheduled work. A late or absent attempt stays visible.
No closed window is backfilled. Within the imported collection, the first
scheduled attempt remains selected; later duplicates cannot replace a known
earlier failed attempt with a better result.

Only the GitHub schedule event is eligible for operational coverage. Pushes and
manual runs are diagnostics. The collector makes no market request outside a
window, after the plan expires, or when the plan is disabled. Captures, failures,
and run identities are preserved in separate artifacts retained for 45 days.
The local auditor requires external GitHub identity and result-hash bindings.
It identifies eligible captures only within the imported collection. Complete
GitHub attempt inventory is not yet independently established, so overall
coverage acceptance stays blocked even when imported captures are valid.
Unbound directories and injected fixtures cannot establish eligible captures.

The cron expressions have no year field. The plan's absolute expiry prevents any
acquisition after 2026-11-20T00:20:00Z; remove the timer after final recovery to
avoid future no-op jobs. Pausing the workflow in GitHub stops future invocations.
Do not rewrite the registered plan to hide a missed or failed window.

This isolated package contains public data code only, with no private database,
financial-account credentials, order-entry gateway, or financial experiment.
Its results do not repair V1/V2, establish profitability, or authorize capital.
The shared HTTP transport is invoked only in DATA mode. Hashes prove consistency
of local evidence, not provider signatures or hostile-host isolation.

Standard public Linux runners and built-in Node APIs are used. No paid service,
personal token, model API, or billing change is configured.
