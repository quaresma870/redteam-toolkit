# can_i_take_over_xyz_fingerprints.json

Vendored from [EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz),
a community-maintained list of services and their dangling-DNS subdomain
takeover fingerprints.

- **License:** CC-BY-4.0. This notice is the required attribution.
- **Source file:** `fingerprints.json` from the `master` branch.
- **Vendored on:** 2026-06-24.
- **Why vendored rather than fetched live:** keeps `subdomain_takeover.py`'s
  tests fast and not network-dependent, and means a transient GitHub outage
  never breaks a scan. Re-sync periodically by re-fetching the same URL —
  this is a point-in-time snapshot, not a live mirror.

## A note on the `vulnerable` field

Only entries with `"vulnerable": true` are used by `subdomain_takeover.py`.
This matters: several historically well-known takeover vectors — GitHub
Pages, Heroku, Netlify, and Shopify among them — are present in this file
for documentation purposes but are marked `"vulnerable": false`, because
those providers have since added mandatory domain-ownership verification
that closes the classic dangling-CNAME takeover path. Re-adding them to
the active fingerprint set without re-confirming they're actually
exploitable again would produce false positives.
