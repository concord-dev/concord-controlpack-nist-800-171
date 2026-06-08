# concord-controlpack-nist-800-171

Concord control pack for **NIST Special Publication 800-171 Rev 2 — Protecting
Controlled Unclassified Information in Nonfederal Systems and Organizations**.

v0.1.0 covers eight controls spanning four families. Each control ships
with real Rego policy and a pass fixture. Every policy is vendored from
upstream Concord control packs (SOC 2 / CIS AWS) and attributed in
`pack.yaml`.

## Controls

| ID | Title | Evidence source | Policy |
|---|---|---|---|
| 3.1.1 | Authorized access | `concord-plugin-okta` | `concord.soc2.cc6_1` |
| 3.1.5 | Least privilege (access reviews) | `concord-plugin-github` (access-review docs) | `concord.soc2.cc6_2` |
| 3.3.1 | Audit records | `concord-plugin-aws` (`cloudtrail_trails`) | `concord.cis_aws.cloudtrail_multi_region` |
| 3.4.1 | Baseline configuration | `concord-plugin-aws` (`s3_bucket_encryption`) | `concord.cis_aws.s3_encryption` |
| 3.5.3 | Multifactor authentication | `concord-plugin-okta` | `concord.soc2.cc6_1` |
| 3.5.7 | Password complexity | `concord-plugin-aws` (`iam_password_policy`) | `concord.cis_aws.iam_password_policy` |
| 3.13.8 | Cryptography in transit | `concord-plugin-cloudflare` (`cloudflare_zones`) | `concord.nist_800_171.crypto_in_transit` |
| 3.13.16 | Cryptography at rest | `concord-plugin-aws` (`s3_bucket_encryption`) | `concord.cis_aws.s3_encryption` |

## Crosswalks

Every control YAML carries `metadata.mappings.*` for **NIST 800-53 Rev 5**,
**SOC 2 Trust Services**, **CMMC L2**, and where applicable **CIS AWS
Foundations Benchmark v2**. The Concord crosswalk dividend: one piece of
evidence, multiple frameworks satisfied.

## Install

```sh
concord add nist-800-171
concord check --framework nist-800-171
```

To evaluate against the bundled pass fixtures only:

```sh
concord check --framework nist-800-171 --fixtures
```

## Attribution

- `cc6_1.rego`, `cc6_2.rego` — vendored from
  [`concord-dev/concord-controlpack-soc2`](https://github.com/concord-dev/concord-controlpack-soc2)
- `cloudtrail.rego`, `iam_password_policy.rego`, `s3_encryption.rego` — vendored from
  [`concord-dev/concord-controlpack-cis-aws`](https://github.com/concord-dev/concord-controlpack-cis-aws)
- `cloudflare_tls.rego` — original to this pack; backed by
  [`concord-dev/concord-plugin-cloudflare`](https://github.com/concord-dev/concord-plugin-cloudflare)
  evidence shape

Control IDs, titles, and family numbering follow [NIST SP 800-171 Rev 2](https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final).
The CMMC L2 crosswalk uses the [CMMC v2 mapping](https://dodcio.defense.gov/CMMC/).
