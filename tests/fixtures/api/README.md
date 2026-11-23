# Canned API responses (dry-run data)

The enrichers read these files instead of calling the network when they run
with `--dry-run`, and the tests use them as realistic sample responses.

**Where they came from:** real responses from the public APIs, fetched on
2026-11-23 for the CVEs in `tests/fixtures/sample.nessus`, then **trimmed**
to the fields the parsers read (to keep the repo small). Field names and
structure are unchanged, so the parsers see exactly what the live APIs send.

| Folder           | API                                  | Trimmed how                                         |
|------------------|--------------------------------------|-----------------------------------------------------|
| `nvd/`           | NVD CVE API 2.0, one file per CVE    | kept id, dates, status, English description, CVSS metrics, CISA fields, weaknesses, first 8 references |
| `kev/`           | CISA KEV JSON feed                   | real header; 3 real entries plus CVE-2021-44228      |
| `epss/`          | FIRST EPSS API, one batched request  | not trimmed                                         |
| `vendor_ubuntu/` | Ubuntu CVE tracker JSON              | kept id, priority, published, packages (focal/jammy/noble/upstream statuses only) |
| `vendor_redhat/` | Red Hat Security Data API            | kept RHEL package_state rows plus 2 others, first 2 affected_release rows |
| `vendor_msrc/`   | MSRC Security Update Guide API       | CVE-2016-2183: real empty answer; CVE-2021-44228: first 3 products (none are Windows) |

**Deliberately missing:** `vendor_ubuntu/CVE-2023-51385.json` and
`vendor_ubuntu/CVE-2008-5161.json`. The Ubuntu API returned HTTP 504 for both
when this set was captured. A missing canned file is reported as a
`lookup_error`, the same as a live outage, so the dry run also shows how a
vendor outage is handled.

These files are real public advisory data, **not** scan data, and contain no
information about any network or client.
