package concord.nist_800_171.crypto_in_transit

import rego.v1

default min_tls_floor := "1.2"

min_tls_floor := x if {
	x := input._concord.params.min_tls_floor
}

default require_dnssec := true

require_dnssec := x if {
	x := input._concord.params.require_dnssec
}

tls_rank := {"1.0": 0, "1.1": 1, "1.2": 2, "1.3": 3}

deny contains msg if {
	not input.cloudflare_zones
	msg := "no Cloudflare zone evidence collected"
}

deny contains msg if {
	count(input.cloudflare_zones.zones) == 0
	msg := "Cloudflare account has zero zones — wrong account or insufficient token scope"
}

deny contains msg if {
	some zone in input.cloudflare_zones.zones
	not zone.compliant
	msg := sprintf("zone %q is non-compliant: %s", [zone.name, zone.reason])
}

deny contains msg if {
	some zone in input.cloudflare_zones.zones
	zone.detail.min_tls_version
	tls_rank[zone.detail.min_tls_version] < tls_rank[min_tls_floor]
	msg := sprintf("zone %q min_tls_version=%v is below NIST 800-171 §3.13.8 floor of %v", [zone.name, zone.detail.min_tls_version, min_tls_floor])
}

deny contains msg if {
	require_dnssec
	some zone in input.cloudflare_zones.zones
	zone.detail.dnssec != "active"
	msg := sprintf("zone %q has DNSSEC %v (policy requires active)", [zone.name, zone.detail.dnssec])
}

warn contains msg if {
	some zone in input.cloudflare_zones.zones
	zone.detail.ssl_mode == "full"
	msg := sprintf("zone %q uses ssl_mode=full (consider strict for origin certificate validation)", [zone.name])
}
