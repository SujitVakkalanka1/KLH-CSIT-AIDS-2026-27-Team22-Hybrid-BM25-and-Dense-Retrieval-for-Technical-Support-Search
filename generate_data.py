#!/usr/bin/env python3
"""
Phase 1: Dataset & Labeled Evaluation Set Generator (Audited & Leak-Checked)
Generates:
  - dataset.json: 250 technical support KB articles (KB-001 to KB-250) across 5 domains.
    Includes 30 hand-written sibling-code, firmware-version, and vocabulary trap articles
    plus 220 varied domain articles with diverse phrasing structures.
  - eval_queries.json: 42 independently written evaluation queries:
    - 14 exact_code queries
    - 14 symptom queries (colloquial phrasing with zero technical keyword overlap)
    - 12 mixed queries (plain-English symptom words + partial error/version code)
    - 2 unanswerable queries (plausible in-domain tech-support questions for nonexistent
      codes/unreleased firmware that no KB article answers)
"""

import json
import random
import re
from pathlib import Path
from typing import Any


STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "because", "by", "can", "do",
    "during", "even", "every", "for", "from", "gets", "go", "goes", "has",
    "have", "how", "i", "if", "in", "into", "is", "it", "its", "keep", "keeps",
    "my", "never", "no", "not", "now", "of", "off", "on", "one", "or", "our",
    "out", "over", "so", "that", "the", "their", "then", "though", "through",
    "to", "up", "when", "whenever", "where", "while", "with", "wont", "after",
    "about", "back", "few", "nothing", "plenty", "quite", "same", "several",
    "slightly", "some", "still", "suddenly", "totally", "two", "under", "very",
}


def get_handwritten_trap_articles() -> list[dict[str, Any]]:
    """
    30 individually hand-written KB articles (KB-001 through KB-030) organized into
    deliberate trap clusters across all 5 technical support domains.
    Written with natural, varied engineering prose—no Mad-Libs templates.
    """
    return [
        # =====================================================================
        # CLUSTER 1: TRAP-AUTH-50X — Sibling OAuth / SSO Handshake Error Codes
        # =====================================================================
        {
            "id": "KB-001",
            "domain": "Auth/IAM",
            "title": "OIDC Token Exchange Aborted Due to Expired RSA Signing Key ID (kid)",
            "error_code": "E_AUTH_501",
            "product": "AegisIAM Gateway v4.2.0",
            "trap_cluster": "TRAP-AUTH-50X: Sibling OAuth/OIDC Handshake Codes",
            "symptom": (
                "Enterprise users attempting single sign-on through the AegisIAM Gateway are redirected "
                "back to the login screen immediately after submitting valid credentials. Gateway trace "
                "logs record E_AUTH_501 during the authorization_code token exchange step because the "
                "upstream identity provider rotated its JWKS public keys and the gateway cache still "
                "references the retired key identifier."
            ),
            "resolution": (
                "Purge the in-memory JWKS key cache on the AegisIAM cluster by running "
                "`aegis-ctl jwks flush --all-nodes` and reduce `jwks_cache_ttl_seconds` from 86400 to "
                "900 in `/etc/aegis/oidc.yaml` so key rollover events propagate automatically."
            ),
        },
        {
            "id": "KB-002",
            "domain": "Auth/IAM",
            "title": "OIDC Token Exchange Rejected by Audience Claim (aud) Mismatch",
            "error_code": "E_AUTH_503",
            "product": "AegisIAM Gateway v4.2.0",
            "trap_cluster": "TRAP-AUTH-50X: Sibling OAuth/OIDC Handshake Codes",
            "symptom": (
                "Single sign-on sessions fail right after the identity provider callback returns to "
                "AegisIAM Gateway. The authentication worker emits E_AUTH_503 when inspecting the "
                "returned ID token payload because the `aud` claim contains the staging client UUID "
                "instead of the production relying-party identifier."
            ),
            "resolution": (
                "Open the relying-party registration in the AegisIAM console, align the `client_id` and "
                "`expected_audience` fields with the production application URI, and redeploy the OIDC "
                "relying-party manifest."
            ),
        },
        {
            "id": "KB-003",
            "domain": "Auth/IAM",
            "title": "PKCE Code Verifier SHA-256 Digest Failure on Mobile SSO Callback",
            "error_code": "E_AUTH_509",
            "product": "AegisIAM Gateway v4.2.0",
            "trap_cluster": "TRAP-AUTH-50X: Sibling OAuth/OIDC Handshake Codes",
            "symptom": (
                "OAuth 2.0 login flows initiated from native iOS and Android clients terminate at the "
                "token endpoint with E_AUTH_509. The gateway rejects the request because the `code_verifier` "
                "string was URL-encoded twice by the mobile HTTP interceptor, causing the S256 hash comparison "
                "against `code_challenge` to fail."
            ),
            "resolution": (
                "Disable automatic percent-encoding on the `code_verifier` form parameter in the mobile "
                "SDK network layer, or upgrade the client library to `aegis-mobile-sdk >= 3.1.4` which "
                "transmits raw RFC 7636 Base64URL characters without double escaping."
            ),
        },

        # =====================================================================
        # CLUSTER 2: TRAP-SSL-10X — Sibling TLS Inspection & mTLS Error Codes
        # =====================================================================
        {
            "id": "KB-004",
            "domain": "Network/Routers",
            "title": "Deep Packet TLS Inspection Drops Downstream Sessions Missing Intermediate CA",
            "error_code": "ERR_SSL_102",
            "product": "NetCore EdgeProxy v3.8.1",
            "trap_cluster": "TRAP-SSL-10X: Sibling TLS Handshake & Certificate Codes",
            "symptom": (
                "Outbound HTTPS connections routed through NetCore EdgeProxy terminate during the ServerHello "
                "phase with ERR_SSL_102. The appliance cannot complete chain verification for external SaaS "
                "hosts whose servers omit the cross-signed intermediate certificate from the TLS handshake."
            ),
            "resolution": (
                "Enable AIA (Authority Information Access) intermediate certificate fetching in the proxy "
                "profile via `set ssl-inspection aia-fetch enable`, then reload the trusted CA bundle with "
                "`netcore-adm cert reload`."
            ),
        },
        {
            "id": "KB-005",
            "domain": "Network/Routers",
            "title": "Mutual TLS Client Certificate Rejected Due to OCSP Stapling Timeout",
            "error_code": "ERR_SSL_108",
            "product": "NetCore EdgeProxy v3.8.1",
            "trap_cluster": "TRAP-SSL-10X: Sibling TLS Handshake & Certificate Codes",
            "symptom": (
                "Partner API webhooks authenticating via mutual TLS (mTLS) to NetCore EdgeProxy are dropped "
                "after a 5-second pause with ERR_SSL_108. Firewall egress rules on the DMZ VLAN block the "
                "appliance from reaching the external OCSP responder URL embedded in the client certificate."
            ),
            "resolution": (
                "Permit outbound TCP port 80/443 traffic from the EdgeProxy management interface to the CA's "
                "OCSP responder subnet, or enable `ocsp_soft_fail_fallback` when crl-distribution caching is "
                "active on the appliance."
            ),
        },
        {
            "id": "KB-006",
            "domain": "Network/Routers",
            "title": "TLS 1.3 Post-Handshake KeyUpdate Frame Triggers Cipher Suite Alert",
            "error_code": "ERR_SSL_109",
            "product": "NetCore EdgeProxy v3.8.1",
            "trap_cluster": "TRAP-SSL-10X: Sibling TLS Handshake & Certificate Codes",
            "symptom": (
                "Long-lived gRPC streams passing through NetCore EdgeProxy sever abruptly after transferring "
                "roughly 1 GB of payload data, logging ERR_SSL_109. The hardware crypto offload card mishandles "
                "TLS 1.3 KeyUpdate messages when ChaCha20-Poly1305 is negotiated."
            ),
            "resolution": (
                "Prioritize `TLS_AES_256_GCM_SHA384` ahead of `TLS_CHACHA20_POLY1305_SHA256` in the ingress "
                "cipher policy, or disable hardware crypto offload for TLS 1.3 rekeying via `sysctl net.nitro.rekey_hw=0`."
            ),
        },

        # =====================================================================
        # CLUSTER 3: TRAP-ROUTER-FW — Router-X1 v2.4.x Point-Release Firmware Traps
        # =====================================================================
        {
            "id": "KB-007",
            "domain": "Network/Routers",
            "title": "BGP Hold-Timer Expiration Under High Route-Reflector Churn on Router-X1 v2.4.1",
            "error_code": "NET_BGP_410",
            "product": "Router-X1 v2.4.1",
            "trap_cluster": "TRAP-ROUTER-FW: Router-X1 v2.4.x Point-Release Regressions",
            "symptom": (
                "After upgrading core border gateways to Router-X1 v2.4.1, eBGP peering sessions flap every "
                "90 seconds whenever full internet routing tables are refreshed. A single-threaded mutex in "
                "the v2.4.1 RIB scanner starves keepalive packet scheduling while sorting prefix updates."
            ),
            "resolution": (
                "Apply hotfix package `rx1-routing-patch-241b.pkg` or enable asynchronous keepalive offloading "
                "with `router bgp keepalive-thread dedicated` in global configuration mode."
            ),
        },
        {
            "id": "KB-008",
            "domain": "Network/Routers",
            "title": "PPPoE WAN Sub-Interface Silent MTU Blackhole on Router-X1 v2.4.4",
            "error_code": "NET_WAN_414",
            "product": "Router-X1 v2.4.4",
            "trap_cluster": "TRAP-ROUTER-FW: Router-X1 v2.4.x Point-Release Regressions",
            "symptom": (
                "Branch offices running Router-X1 v2.4.4 over fiber PPPoE uplinks can ping external IP "
                "addresses normally, but TLS handshakes and large HTTP responses stall indefinitely. Firmware "
                "v2.4.4 fails to subtract the 8-byte PPPoE encapsulation header when computing TCP MSS clamping."
            ),
            "resolution": (
                "Manually clamp the TCP Maximum Segment Size on the dialer interface by configuring "
                "`interface pppoe0 ip tcp adjust-mss 1452` until upgrading past v2.4.4."
            ),
        },
        {
            "id": "KB-009",
            "domain": "Network/Routers",
            "title": "OSPFv3 IPv6 Link-Local Neighbor Stuck in EXSTART State on Router-X1 v2.4.9",
            "error_code": "NET_OSPF_419",
            "product": "Router-X1 v2.4.9",
            "trap_cluster": "TRAP-ROUTER-FW: Router-X1 v2.4.x Point-Release Regressions",
            "symptom": (
                "Dual-stack core links running Router-X1 v2.4.9 fail to complete OSPFv3 adjacency formation, "
                "remaining permanently trapped in the EXSTART/EXCHANGE state. Build v2.4.9 introduces a "
                "regression in 802.1Q VLAN tag stripping on IPv6 Database Description (DBD) multicast frames."
            ),
            "resolution": (
                "Disable hardware VLAN RX stripping on the trunk port using `ethtool -K eth2 rxvlan off` "
                "or roll back the routing engine image to `Router-X1 v2.4.7-LTS`."
            ),
        },

        # =====================================================================
        # CLUSTER 4: TRAP-SWITCH-FW — OmniSwitch-48P v5.1.x Firmware Traps
        # =====================================================================
        {
            "id": "KB-010",
            "domain": "Network/Routers",
            "title": "802.3bt PoE++ Class 6 Power Denial After Warm Reboot on OmniSwitch-48P v5.1.2",
            "error_code": "SW_POE_212",
            "product": "OmniSwitch-48P v5.1.2",
            "trap_cluster": "TRAP-SWITCH-FW: OmniSwitch-48P v5.1.x Firmware Traps",
            "symptom": (
                "Wi-Fi 6E access points and PTZ cameras connected to OmniSwitch-48P v5.1.2 fail to power up "
                "following a warm software reload, logging SW_POE_212. The microcontroller power budget table "
                "retains stale pre-reboot wattage allocations and refuses Class 6 LLDP power requests."
            ),
            "resolution": (
                "Reset the PoE controller bank without dropping switching traffic via `poe controller reset slot 1`, "
                "and enable `lldp med-power-negotiation strict` per port."
            ),
        },
        {
            "id": "KB-011",
            "domain": "Network/Routers",
            "title": "LACP Port-Channel Split-Brain During Fast-Timer Failover on OmniSwitch-48P v5.1.8",
            "error_code": "SW_LACP_218",
            "product": "OmniSwitch-48P v5.1.8",
            "trap_cluster": "TRAP-SWITCH-FW: OmniSwitch-48P v5.1.x Firmware Traps",
            "symptom": (
                "Uplink aggregation groups on OmniSwitch-48P v5.1.8 drop both member links simultaneously "
                "with SW_LACP_218 when 1-second fast LACP PDU intervals are enabled alongside spanning-tree "
                "portfast trunking."
            ),
            "resolution": (
                "Switch the LACP periodic timer from `fast` (1s) to `normal` (30s) on the aggregate interface "
                "via `lacp timeout long`, or install ASIC microcode patch `os48p-518-lacp.bin`."
            ),
        },

        # =====================================================================
        # CLUSTER 5: TRAP-DB-LOCK — Sibling Storage & Database Lock Error Codes
        # =====================================================================
        {
            "id": "KB-012",
            "domain": "Database/Storage",
            "title": "Write-Ahead Log (WAL) Checkpoint Fsync Stall on ZFS VolBlockSize Mismatch",
            "error_code": "DB_LOCK_801",
            "product": "ChronosDB v6.3.0",
            "trap_cluster": "TRAP-DB-LOCK: Sibling Database Lock & Consensus Codes",
            "symptom": (
                "High-throughput OLTP clusters running ChronosDB v6.3.0 freeze all incoming INSERT and UPDATE "
                "statements every 15 minutes with DB_LOCK_801. Background checkpoint workers block on `fdatasync` "
                "because the underlying ZFS dataset uses a 128 KB recordsize while ChronosDB writes 8 KB pages, "
                "causing severe read-modify-write amplification."
            ),
            "resolution": (
                "Align the storage dataset block size to the database page geometry (`zfs set recordsize=8k tank/chronos`) "
                "and set `wal_writer_delay_ms = 20` in `chronos.conf`."
            ),
        },
        {
            "id": "KB-013",
            "domain": "Database/Storage",
            "title": "Distributed Foreign-Key Gap Lock Deadlock Across Partitioned Shards",
            "error_code": "DB_LOCK_804",
            "product": "ChronosDB v6.3.0",
            "trap_cluster": "TRAP-DB-LOCK: Sibling Database Lock & Consensus Codes",
            "symptom": (
                "Batch upsert jobs executing under SERIALIZABLE isolation abort with DB_LOCK_804 when two "
                "worker threads concurrently insert child rows referencing the same parent composite key across "
                "hash-partitioned shards."
            ),
            "resolution": (
                "Downgrade batch ingestion sessions to `READ COMMITTED` isolation or sort input rows deterministically "
                "by `(tenant_id, parent_id)` prior to beginning the multi-shard transaction."
            ),
        },
        {
            "id": "KB-014",
            "domain": "Database/Storage",
            "title": "Raft Quorum Lease Expiration Causes Read-Only Split-Brain Fencing",
            "error_code": "DB_LOCK_809",
            "product": "ChronosDB v6.3.0",
            "trap_cluster": "TRAP-DB-LOCK: Sibling Database Lock & Consensus Codes",
            "symptom": (
                "Primary storage nodes demote themselves to read-only followers and reject client writes with "
                "DB_LOCK_809 during cross-AZ network jitter. The Raft leader lease timer (`500ms`) expires before "
                "heartbeat acknowledgments return from the witness node in the third availability zone."
            ),
            "resolution": (
                "Increase `raft_leader_lease_ms` to `1500` and `raft_election_timeout_ms` to `4500` in the cluster "
                "consensus configuration, and verify NTP clock drift across nodes is below 10ms."
            ),
        },

        # =====================================================================
        # CLUSTER 6: TRAP-CLI-90X — Sibling Cloud CLI & Container Runtime Codes
        # =====================================================================
        {
            "id": "KB-015",
            "domain": "Cloud/CLI",
            "title": "NimbusCLI Deployment Fails When Exec-Credential Plugin Emits v1alpha1 Schema",
            "error_code": "CLI_ERR_901",
            "product": "NimbusCLI v2.9.0",
            "trap_cluster": "TRAP-CLI-90X: Sibling Cloud CLI Execution Codes",
            "symptom": (
                "Running `nimbus deploy --cluster prod` after upgrading to NimbusCLI v2.9.0 immediately exits "
                "with CLI_ERR_901. The local kubeconfig file invokes an external authentication helper binary "
                "configured with retired `client.authentication.k8s.io/v1alpha1` API version."
            ),
            "resolution": (
                "Update the `users[].user.exec.apiVersion` field in `~/.kube/config` to "
                "`client.authentication.k8s.io/v1` and upgrade the helper plugin via `nimbus components update auth-exec`."
            ),
        },
        {
            "id": "KB-016",
            "domain": "Cloud/CLI",
            "title": "STS AssumeRole Chaining Exceeds 1-Hour Session Ceiling in CI Pipelines",
            "error_code": "CLI_ERR_902",
            "product": "NimbusCLI v2.9.0",
            "trap_cluster": "TRAP-CLI-90X: Sibling Cloud CLI Execution Codes",
            "symptom": (
                "Automated Terraform and NimbusCLI deployment pipelines fail midway through multi-region "
                "rollouts with CLI_ERR_902. Because the runner assumes an intermediate jump role before "
                "assuming the target workload role, AWS/Nimbus STS enforces a hard 3600-second maximum "
                "session duration regardless of `--duration-seconds 14400`."
            ),
            "resolution": (
                "Configure OIDC federated workload identity directly against the target deployment role "
                "to eliminate role-chaining, or invoke `nimbus auth refresh-token --auto` before each stage."
            ),
        },
        {
            "id": "KB-017",
            "domain": "Cloud/CLI",
            "title": "OCI Image Index Multi-Arch Manifest Digest Mismatch on ARM64 Nodes",
            "error_code": "CLI_ERR_907",
            "product": "NimbusCLI v2.9.0",
            "trap_cluster": "TRAP-CLI-90X: Sibling Cloud CLI Execution Codes",
            "symptom": (
                "Pushing or deploying container images via `nimbus image promote` fails on Graviton/ARM64 "
                "worker pools with CLI_ERR_907. Docker Buildx stripped the `linux/arm64/v8` platform attestation "
                "layer when copying the image across regional registries."
            ),
            "resolution": (
                "Re-publish the multi-architecture manifest list using `nimbus registry copy --preserve-digests --all-platforms` "
                "instead of pulling and re-tagging a single-arch layer locally."
            ),
        },

        # =====================================================================
        # CLUSTER 7: TRAP-DISPLAY-HW — Sibling DisplayPort / HDMI / USB-C Codes
        # =====================================================================
        {
            "id": "KB-018",
            "domain": "Display/Hardware",
            "title": "DisplayPort 1.4 MST Daisy-Chain Blacks Out Third Monitor Due to HBR3 Link Training Loss",
            "error_code": "DISP_EDID_301",
            "product": "ProDock ThunderHub G4",
            "trap_cluster": "TRAP-DISPLAY-HW: Sibling Display & Docking Station Codes",
            "symptom": (
                "When three 4K monitors are daisy-chained through the ProDock ThunderHub G4 using DisplayPort "
                "Multi-Stream Transport (MST), the final display in the chain remains dark and logs DISP_EDID_301. "
                "Uncompressed 10-bit color exceeds available HBR3 lane bandwidth."
            ),
            "resolution": (
                "Reduce color depth on the secondary monitors from 10 bpc to 8 bpc in the GPU driver panel, "
                "or enable Display Stream Compression (DSC 1.2) on the ProDock dip-switch bank."
            ),
        },
        {
            "id": "KB-019",
            "domain": "Display/Hardware",
            "title": "HDMI 2.1 Ultra-High-Speed Handshake Fails with HDCP 2.3 Repeater Repeal",
            "error_code": "DISP_EDID_305",
            "product": "ProDock ThunderHub G4",
            "trap_cluster": "TRAP-DISPLAY-HW: Sibling Display & Docking Station Codes",
            "symptom": (
                "Connecting an external 4K 120Hz OLED display to the ProDock ThunderHub G4 HDMI 2.1 port "
                "results in a blank screen and code DISP_EDID_305 whenever protected media or DRM browser "
                "tabs are opened. The dock's internal signal repeater table overflows after 7 downstream KSV IDs."
            ),
            "resolution": (
                "Flash the dock's Synaptics VMM6210 MST controller firmware to v4.08.12 using `prodock-fw-updater` "
                "to clear the HDCP 2.3 KSV FIFO buffer."
            ),
        },
        {
            "id": "KB-020",
            "domain": "Display/Hardware",
            "title": "USB-C Power Delivery PDO Renegotiation Causes Momentary External Monitor Disconnect",
            "error_code": "DISP_PWR_309",
            "product": "ProDock ThunderHub G4",
            "trap_cluster": "TRAP-DISPLAY-HW: Sibling Display & Docking Station Codes",
            "symptom": (
                "External monitors attached to the ProDock ThunderHub G4 disconnect for 3 seconds and emit "
                "DISP_PWR_309 whenever a mobile workstation turbo-boosts under heavy CPU/GPU load. The dock's "
                "100W PD controller triggers an over-current protection reset on the VBUS rail."
            ),
            "resolution": (
                "Connect the dedicated 180W barrel power brick to the ProDock ThunderHub G4 and set BIOS "
                "`USB-C Dynamic Power Peak Shift` to `Disabled` on the host laptop."
            ),
        },
        {
            "id": "KB-021",
            "domain": "Auth/IAM",
            "title": "Hardware FIDO2 WebAuthn Passkey Attestation Rejected on Resident Key Overflow",
            "error_code": "E_AUTH_512",
            "product": "AegisIAM Gateway v4.2.0",
            "trap_cluster": "TRAP-AUTH-50X: Sibling OAuth/OIDC Handshake Codes",
            "symptom": (
                "Passwordless enrollment with USB-C security keys fails on AegisIAM Gateway v4.2.0 with E_AUTH_512. "
                "The relying party requests `residentKey: required` on hardware tokens whose 25-slot discoverable "
                "credential storage is already full."
            ),
            "resolution": (
                "Delete unused discoverable credentials from the security key using `ykman fido credentials delete`, "
                "or change the AegisIAM WebAuthn policy to `residentKey: preferred` for non-discoverable fallback."
            ),
        },

        # =====================================================================
        # CLUSTER 8: TRAP-VOCAB-SYMPTOM — Formal Technical Prose vs. Everyday User Language
        # (Written so Symptom Queries have ZERO technical keyword overlap!)
        # =====================================================================
        {
            "id": "KB-022",
            "domain": "Network/Routers",
            "title": "Executing Non-Volatile NVRAM Factory Initialization and Configuration Decommissioning",
            "error_code": "SYS_NVRAM_001",
            "product": "OmniGate Branch Appliance",
            "trap_cluster": "TRAP-VOCAB-SYMPTOM: Formal Jargon vs. Colloquial User Symptoms",
            "symptom": (
                "Administrators decommissioning an OmniGate Branch Appliance or recovering from corrupted "
                "startup parameters must purge all persistent NVRAM sectors, cryptographic keystores, and "
                "custom routing tables to restore the baseline OEM provisioning image."
            ),
            "resolution": (
                "Depress the recessed rear chassis micro-actuator for 15 seconds while cycling DC power until "
                "the amber status indicator illuminates solidly, or execute `system nvram sanitize --oem-baseline` "
                "from the serial console."
            ),
        },
        {
            "id": "KB-023",
            "domain": "Display/Hardware",
            "title": "Mitigating Panel Vertical Blanking Interval (VBI) Refresh Rate Desynchronization",
            "error_code": "HW_VBI_704",
            "product": "UltraView 32Q Studio Reference Display",
            "trap_cluster": "TRAP-VOCAB-SYMPTOM: Formal Jargon vs. Colloquial User Symptoms",
            "symptom": (
                "Variable Refresh Rate (VRR) operation on the UltraView 32Q Studio Reference Display exhibits "
                "periodic luminance oscillation and brief loss of raster scan lock when GPU frame delivery "
                "fluctuates near the 48 Hz LFC boundary."
            ),
            "resolution": (
                "Disable Adaptive-Sync in the monitor OSD menu under `Signal Timing -> VRR Control`, and lock "
                "the host graphics output to a fixed 120 Hz vertical refresh timing."
            ),
        },
        {
            "id": "KB-024",
            "domain": "Display/Hardware",
            "title": "Lithium-Ion Pack Under-Voltage Lockout (UVLO) Pre-Charge Trickle Wake Procedure",
            "error_code": "PWR_UVLO_119",
            "product": "AeroBook Pro 16 Workstation",
            "trap_cluster": "TRAP-VOCAB-SYMPTOM: Formal Jargon vs. Colloquial User Symptoms",
            "symptom": (
                "Units stored unpowered for extended periods enter battery management IC under-voltage lockout "
                "(UVLO) protection when cell potential drops below 2.5V per cell, preventing Embedded Controller "
                "(EC) power-rail sequencing and illumination of chassis indicators."
            ),
            "resolution": (
                "Connect a direct 140W USB-PD power supply to port TB1 for a minimum of 45 minutes without "
                "actuating the power switch, then perform an EC hard-reset by holding the chassis power key "
                "for 30 seconds."
            ),
        },
        {
            "id": "KB-025",
            "domain": "Network/Routers",
            "title": "802.11ax Captive Portal DNS Interceptor Loop Due to DoH/Private Relay Bypass",
            "error_code": "WLAN_CAP_330",
            "product": "AirPulse Hospitality Controller",
            "trap_cluster": "TRAP-VOCAB-SYMPTOM: Formal Jargon vs. Colloquial User Symptoms",
            "symptom": (
                "Wireless guest stations associate to the open SSID and obtain an RFC 1918 DHCP lease, but the "
                "HTTP 302 authentication splash screen fails to render because client-side encrypted DNS-over-HTTPS "
                "(DoH) ignores the controller's synthetic DNS redirect response."
            ),
            "resolution": (
                "Enable RFC 8910 Captive Portal API DHCP Option 114 on the AirPulse VLAN scope so modern OS "
                "supplicants discover the authentication portal URI natively without relying on DNS interception."
            ),
        },
        {
            "id": "KB-026",
            "domain": "Database/Storage",
            "title": "NVMe Namespace Thermal Throttling and DRAM Write-Back Cache Saturation Stall",
            "error_code": "STOR_NVME_612",
            "product": "VelocityFlash U.3 Enterprise Array",
            "trap_cluster": "TRAP-VOCAB-SYMPTOM: Formal Jargon vs. Colloquial User Symptoms",
            "symptom": (
                "Sustained sequential ingress exceeding 60 GB diminishes host I/O throughput to sub-15 MB/s "
                "and elevates queue latency above 4000ms as controller die temperature crosses the 78°C "
                "composite thermal threshold and exhausts SLC pseudo-cache."
            ),
            "resolution": (
                "Increase chassis fan PWM duty cycle to a minimum of 65% via IPMI, verify heatsink thermal pad "
                "contact across the PCIe Gen5 riser, and enable `nvme set-feature -f 0x04` progressive thermal management."
            ),
        },
        {
            "id": "KB-027",
            "domain": "Auth/IAM",
            "title": "SAML 2.0 Assertion NotBefore/NotOnOrAfter Validation Rejection from NTP Drift",
            "error_code": "IAM_SAML_408",
            "product": "AegisIAM Federation Broker",
            "trap_cluster": "TRAP-VOCAB-SYMPTOM: Formal Jargon vs. Colloquial User Symptoms",
            "symptom": (
                "Federated browser authentication attempts reject incoming XML assertions when the service "
                "provider system clock precedes the identity provider's issuance timestamp by more than the "
                "configured 500-millisecond tolerance window."
            ),
            "resolution": (
                "Synchronize the host chronyd daemon against stratum-1 NTP peers (`chronyc makestep`) and "
                "configure `assertion_clock_skew_tolerance_seconds: 60` in the SAML service provider profile."
            ),
        },
        {
            "id": "KB-028",
            "domain": "Cloud/CLI",
            "title": "Kubelet Ephemeral Storage Inode Exhaustion Triggers Pod Eviction Manager",
            "error_code": "K8S_NODE_771",
            "product": "NimbusGrid Managed Kubernetes",
            "trap_cluster": "TRAP-VOCAB-SYMPTOM: Formal Jargon vs. Colloquial User Symptoms",
            "symptom": (
                "Workloads scheduled on worker nodes terminate unexpectedly with `Evicted` status even though "
                "`df -h` reports over 70% free gigabytes on `/var/lib/containerd`. Millions of zero-byte "
                "unlinked temporary files have consumed 100% of the ext4 filesystem inode table (`df -i`)."
            ),
            "resolution": (
                "Prune exited container layers and orphaned overlayfs directories via `crictl rmi --prune`, "
                "and enforce `resources.limits.ephemeral-storage` on jobs generating high small-file counts."
            ),
        },
        {
            "id": "KB-029",
            "domain": "Database/Storage",
            "title": "PostgreSQL Transaction ID (XID) Wraparound Protection Forces Emergency Vacuum Mode",
            "error_code": "PG_XID_990",
            "product": "CloudPG Managed Relational Service",
            "trap_cluster": "TRAP-VOCAB-SYMPTOM: Formal Jargon vs. Colloquial User Symptoms",
            "symptom": (
                "The relational cluster refuses all DML mutations and raises `database is not accepting commands "
                "to avoid wraparound data loss` because a long-running orphaned replication slot prevented "
                "autovacuum from advancing `relfrozenxid` past the 2-billion transaction horizon."
            ),
            "resolution": (
                "Drop the abandoned logical replication slot via `SELECT pg_drop_replication_slot('stale_slot');` "
                "and execute `VACUUM FREEZE VERBOSE;` across the highest-age relations in single-user mode."
            ),
        },
        {
            "id": "KB-030",
            "domain": "Display/Hardware",
            "title": "Acoustic Coil Whine From MLCC Piezoelectric Resonance Under C-State Residency",
            "error_code": "HW_VRM_502",
            "product": "TitanStation Z9 Tower",
            "trap_cluster": "TRAP-VOCAB-SYMPTOM: Formal Jargon vs. Colloquial User Symptoms",
            "symptom": (
                "Multilayer ceramic capacitors (MLCCs) adjacent to the CPU voltage regulator module (VRM) "
                "emit an audible 14 kHz acoustic frequency oscillation when processor cores transition rapidly "
                "between C1E and C6 deep power-saving states during idle desktop operation."
            ),
            "resolution": (
                "Enter UEFI Setup -> Advanced Processor Power Management, disable `Package C-State Limit C6/C7`, "
                "and set `VRM Switching Frequency` to `400 kHz Fixed` to shift resonance outside the audible spectrum."
            ),
        },
    ]


def generate_varied_filler_articles() -> list[dict[str, Any]]:
    """
    Generates the remaining 220 KB articles (KB-031 to KB-250) so that each of the
    5 domains has exactly 50 articles total across the 250-article corpus.
    Carefully audited so NO filler scenario duplicates or collides with the 40
    answerable evaluation queries targeting KB-001..KB-030.
    """
    rng = random.Random(20261115)

    domain_specs = {
        "Auth/IAM": {
            "count": 45,
            "code_prefix": "E_IAM",
            "code_start": 601,
            "products": [
                "VaultGuard Directory Sync v2.3",
                "KeyPulse RADIUS Server v5.0",
                "ZeroTrust PAM Broker v1.9",
                "SentinelSSO SCIM Connector v3.4",
                "CertAuthority PKI Responder v1.2",
            ],
            "components": [
                ("LDAP bind connection pool", "Active Directory Domain Controller LDAPS port 636", "connection reset by peer during recursive nested group enumeration"),
                ("HOTP hardware counter synchronization", "RFC 4226 event-based token validation", "counter desynchronization after 10 consecutive button presses without authentication"),
                ("SCIM 2.0 user provisioning webhook", "outbound HR directory connector", "HTTP 409 conflict on duplicate employeeNumber attribute mapping"),
                ("Kerberos SPNEGO ticket validator", "keytab KVNO version counter", "GSSAPI checksum verification error after service account password rotation"),
                ("SAML single logout (SLO) handler", "HTTP-POST binding endpoint", "missing SessionIndex parameter in IdP-initiated logout request"),
                ("PAM SSH certificate authority", "ed25519 host principal signer", "principals list mismatch when connecting via internal DNS CNAME alias"),
                ("RADIUS 802.1X EAP-TLS authenticator", "CRL distribution point fetcher", "stale certificate revocation list blocking wired 802.1X supplicant authentication"),
                ("RBAC policy compiler", "OPA Rego bundle evaluator", "recursion limit exceeded on deeply nested organizational unit hierarchies"),
                ("Privileged session keystroke logger", "encrypted audit spooler queue", "audit daemon blocks interactive sudo shell when remote syslog collector is unreachable"),
            ],
            "fixes": [
                "enable paging with `ldap_page_size = 500` and switch the bind URI to the Global Catalog port 3269",
                "resynchronize the HOTP moving factor counter by submitting two sequential token codes in `/admin/hotp-resync`",
                "run `scim-sync reconcile --dedup-employee-number` and patch the attribute mapping schema to lowercase `userName`",
                "regenerate `/etc/krb5.keytab` using `ktutil` with the updated KVNO and restart the `gssproxy` daemon",
                "enable `allow_unsigned_slo_fallback = true` or configure the IdP to include `<samlp:SessionIndex>` in LogoutRequest XML",
                "append the CNAME alias to `ValidPrincipals` in the SSH CA signing template and re-issue the host certificate",
                "update the cron job fetching the CA CRL every 4 hours and execute `radiusd -X -HUP` to reload in-memory revocation tables",
                "flatten cyclic group memberships in the identity graph before compiling the OPA policy bundle",
                "enable local disk ring-buffer fallback (`audit_spool_fallback = local`) so SSH sessions continue during collector maintenance",
            ],
        },
        "Network/Routers": {
            "count": 40,
            "code_prefix": "NET_RT",
            "code_start": 701,
            "products": [
                "VeloCore SD-WAN Edge 800",
                "AeroMesh Campus Gateway v3.1",
                "PacketShield Core Firewall v6.4",
                "OptiRoute MPLS Provider Edge v4.0",
                "PulseWave Wi-Fi 6E Controller v7.1",
            ],
            "components": [
                ("IPsec IKEv2 site-to-site tunnel", "Diffie-Hellman Group 14 Child SA rekeying", "tunnel phase-2 security associations drop every 28800 seconds due to PFS group mismatch with remote peer"),
                ("VRRP high-availability virtual MAC", "ARP gratuitous broadcast suppression", "upstream aggregation switch continues forwarding frames to standby router after failover"),
                ("DHCPv4 relay agent (ip helper-address)", "Option 82 circuit-ID insertion", "ISC Kea server drops DISCOVER packets containing zero-length giaddr fields"),
                ("BGP route-map prefix-list filter", "AS-PATH regular expression evaluator", "inbound customer prefixes leaked to transit peer due to missing explicit deny clause"),
                ("802.1Q VLAN native trunk port", "Rapid PVST+ BPDU guard state machine", "access port enters err-disable state immediately when an unmanaged VoIP phone bridges untagged frames"),
                ("NetFlow v9 telemetry exporter", "UDP collector template refresh timer", "flow analyzer displays unknown protocol IDs because template definition packets are rate-limited"),
                ("SNMPv3 USM polling engine", "AES-128 privacy boot counter synchronization", "NMS collector receives usmStatsNotInTimeWindows report PDUs after chassis cold boot"),
                ("mDNS / Bonjour multicast reflector", "IGMPv3 snooping querier table", "wireless AirPlay and Chromecast discovery fails across segmented enterprise VLANs"),
            ],
            "fixes": [
                "align Phase 2 Perfect Forward Secrecy (PFS) to `dh-group20` on both endpoints and clear active SAs via `clear crypto ikev2 sa`",
                "configure `vrrp garp-interval 5` on the virtual interface and enable MAC table flush notification on the uplink trunk",
                "set `ip dhcp relay information trust-all` on the ingress SVI or disable Option 82 spoofing protection",
                "append `route-map TRANSIT_OUT deny 999` and run `clear ip bgp * soft out` to withdraw unauthorized routes",
                "enable `spanning-tree bpdufilter enable` selectively on the voice access port and recover the interface with `shutdown` / `no shutdown`",
                "lower `ip flow-export template timeout-rate` to 60 seconds and exempt UDP port 2055 from control-plane policing",
                "increment `snmp-server engineID boots` in NVRAM and resynchronize the SNMPv3 USM user credentials on the poller",
                "enable the internal IGMP snooping querier on both VLANs and add `_ipp._tcp.local` to the mDNS service allowlist",
            ],
        },
        "Database/Storage": {
            "count": 45,
            "code_prefix": "DB_STOR",
            "code_start": 1001,
            "products": [
                "HyperKV In-Memory Cluster v4.8",
                "CephScale Object Gateway v18.2",
                "ShardMatrix Distributed SQL v3.5",
                "ArchiveVault Tape & Cold Tier v2.1",
                "StreamLog TimeSeries Engine v5.0",
            ],
            "components": [
                ("B-tree index page split operation", "concurrent high-velocity UUIDv4 primary key inserts", "index bloat exceeding 65% and buffer pool page eviction thrashing"),
                ("change-data-capture (CDC) Debezium connector", "large Avro schema registry payload", "Kafka connect task throws SerializationException when decimal precision exceeds 38 digits"),
                ("iSCSI multipath MPIO initiator", "ALUA asymmetric active/optimized path switchover", "Linux initiator logs path-down warnings when storage controller A undergoes maintenance"),
                ("HyperKV RDB background snapshot (`bgsave`)", "Linux kernel transparent huge pages (THP)", "copy-on-write memory footprint doubles during fork() and triggers OOM-killer"),
                ("PgBouncer transaction pooling proxy", "JDBC prepared statement session state", "ERROR: prepared statement S_1 already exists when backend connections are recycled across clients"),
                ("S3-compatible object lifecycle expiry worker", "bucket versioning noncurrent transition rules", "delete markers accumulate without reclaiming raw Ceph OSD placement group capacity"),
                ("columnar analytical parquet compaction job", "out-of-core sort spill directory", "scratch quota exceeded on `/var/tmp` during multi-way merge of unpartitioned staging tables"),
                ("RAID-6 parity reconstruction task", "SAS 12Gbps expander backplane", "background array rebuild progresses below 5 MB/s after hot-spare activation"),
                ("connection pooler TCP listener", "ephemeral port range exhaustion", "new client connections fail with EADDRNOTAVAIL under 15,000 short-lived serverless queries/sec"),
            ],
            "fixes": [
                "migrate primary keys from random UUIDv4 to time-ordered UUIDv7 and run `REINDEX INDEX CONCURRENTLY` during off-peak hours",
                "configure `decimal.handling.mode = string` in the Debezium connector JSON configuration and restart the worker task",
                "set `no_path_retry 5` and `polling_interval 2` in `/etc/multipath.conf` followed by `multipath -r`",
                "disable Transparent Huge Pages via `echo never > /sys/kernel/mm/transparent_hugepage/enabled` and set `vm.overcommit_memory = 1`",
                "append `prepareThreshold=0` to the PostgreSQL JDBC connection string or enable `max_prepared_statements = 200` in PgBouncer 1.21+",
                "configure an explicit `NoncurrentVersionExpiration` rule in the bucket lifecycle XML and run `radosgw-admin gc process`",
                "relocate `temp_tablespaces` to a dedicated scratch volume and partition the staging table by `event_date`",
                "raise background rebuild I/O priority via `megacli -AdpSetProp RebuildRate -60 -aALL` during off-peak maintenance windows",
                "expand `net.ipv4.ip_local_port_range = 10240 65535` and enable `net.ipv4.tcp_tw_reuse = 1` on the proxy host",
            ],
        },
        "Cloud/CLI": {
            "count": 46,
            "code_prefix": "CLD_OPS",
            "code_start": 1201,
            "products": [
                "TerraStack IaC Runner v1.7",
                "MeshProxy Envoy Control Plane v2.4",
                "FluxPipe Serverless Engine v3.1",
                "SkyWatch Telemetry Agent v4.0",
                "ArgoFleet GitOps Reconciler v2.10",
            ],
            "components": [
                ("Horizontal Pod Autoscaler (HPA) metrics adapter", "custom Prometheus scrape endpoint", "autoscaler reports `FailedGetResourceMetric` because metrics-server TLS certificate lacks Node IP SANs"),
                ("TerraStack remote state DynamoDB lock", "aborted CI runner SIGKILL cancellation", "subsequent pipeline runs fail with `Error acquiring the state lock: ConditionalCheckFailedException`"),
                ("CoreDNS cluster-internal resolver", "Linux conntrack UDP table exhaustion", "intermittent 5-second DNS lookup timeouts (`ndots:5`) on high-concurrency microservice pods"),
                ("Envoy sidecar proxy mTLS rotation", "istiod SDS Unix domain socket", "503 UC (Upstream Connection Termination) errors when root CA bundle rotates without pod restart"),
                ("Ingress NGINX controller configmap reload", "large lua-resty upstream header payload", "HTTP 502 Bad Gateway returned when upstream response headers exceed 4 KB buffer"),
                ("Serverless function cold-start init phase", "VPC ENI attachment provisioning", "invocation times out after 10 seconds while waiting for subnet IP address allocation"),
                ("Helm chart 3-way strategic merge upgrade", "pending-upgrade release secret state", "`helm upgrade --install` aborts with `another operation (install/upgrade/rollback) is in progress`"),
                ("Containerd CRI image pull credential helper", "private registry pull-secret rotation", "ImagePullBackOff on newly scaled nodes due to cached expired dockerconfigjson credentials"),
                ("Cloud NAT gateway outbound SNAT port allocation", "single destination API IP bottleneck", "SYN packets dropped with `OUT_OF_RESOURCES` when 64,512 ports per NAT IP are saturated"),
            ],
            "fixes": [
                "pass `--kubelet-insecure-tls` or enable `serverTLSBootstrap: true` in the Kubelet configuration and approve pending CSRs",
                "verify no active apply job is running and release the orphaned lock record using `terrastack force-unlock <LOCK_ID>`",
                "deploy `NodeLocal DNSCache` as a DaemonSet and add `options single-request-reopen` to the pod `/etc/resolv.conf` template",
                "verify the `istio-security` volume mount uses projected service account tokens and trigger `istioctl proxy-config secret` refresh",
                "set `proxy-buffer-size: 16k` and `proxy-buffers-number: 8` in the `ingress-nginx-controller` ConfigMap",
                "enable Hyperplane shared ENI pre-warming on the serverless VPC connector and expand the private subnet CIDR block",
                "inspect `helm history <release>` and roll back the stuck state via `helm rollback <release>` before re-applying",
                "patch the service account `imagePullSecrets` reference and restart containerd (`systemctl restart containerd`) on affected workers",
                "enable Dynamic Port Allocation (`minPortsPerVm = 1024`, `maxPortsPerVm = 32768`) and attach two additional elastic NAT IP addresses",
            ],
        },
        "Display/Hardware": {
            "count": 44,
            "code_prefix": "HW_DISP",
            "code_start": 1401,
            "products": [
                "OptiTouch 27 Interactive Kiosk",
                "CineView 40 Ultrawide Monitor",
                "RackConsole 1U KVM Drawer",
                "PrecisionPen Wacom Digitizer Pad",
                "MatrixWall Video Wall Controller v3",
            ],
            "components": [
                ("Thunderbolt 4 PCIe tunnel enumeration", "DMA kernel IOMMU protection policy", "external PCIe capture card fails to initialize until user logs into desktop session"),
                ("IPS panel hardware LUT calibration engine", "USB-B upstream HID communication bridge", "DisplayCal hardware profiling aborts at patch 24 because USB selective suspend drops the serial link"),
                ("capacitive 10-point multi-touch digitizer", "EMI ground-loop interference on unshielded AC adapter", "phantom ghost touches register along the bottom bezel whenever the kiosk thermal printer activates"),
                ("discrete GPU MUX switch (Advanced Optimus)", "eDP internal panel backlight PWM controller", "laptop internal screen stays locked at 10% brightness after waking from S0ix modern standby"),
                ("PCIe Gen5 x16 graphics riser cable", "motherboard BIOS link speed auto-negotiation", "WHEA-Logger Event ID 17 PCIe bus correctable errors appear in Windows Event Viewer"),
                ("KVM switch USB HID emulation processor", "wireless 8000Hz polling rate gaming mouse", "cursor movement stutters when switching between Host A and Host B on the rack console"),
                ("OLED panel pixel-shift compensation cycle", "DDC/CI standby power state monitor", "automatic pixel refresh notification banner interrupts full-screen digital signage mode after 4 hours"),
                ("active optical HDMI 2.0 fiber cable", "source port 5V 55mA current draw limit", "transceiver photodiodes fail to power up over 30-meter conference room runs without external USB power"),
            ],
            "fixes": [
                "authorize the Thunderbolt device permanently via `boltctl enroll --chain <UUID>` or set BIOS DMA Kernel Protection to `Pre-Boot ACL`",
                "disable `USB Selective Suspend` in the active OS power plan and connect the USB-B upstream cable directly to a root motherboard port",
                "bond the kiosk chassis ground lug to earth ground and recalibrate the touch controller baseline via `optitouch-cal --noise-filter high`",
                "update the NVIDIA/AMD GOP VBIOS firmware and switch display mode from `Dynamic MUX` to `dGPU Direct` in UEFI setup",
                "explicitly lock `PCIEX16_1 Link Speed` to `Gen4` in the motherboard BIOS PCI_E configuration menu",
                "connect high-polling-rate peripherals to the KVM's dedicated USB 2.0 pass-through hub port rather than the emulated hotkey port",
                "defer automatic maintenance cycles to standby hours via OSD `OLED Care -> Pixel Refresh -> Run Only in Standby`",
                "attach the micro-USB power injector pigtail on the display end of the active optical HDMI cable to a 5V 1A USB port",
            ],
        },
    }

    narrative_patterns = [
        lambda comp, ctx, issue, prod, code, env: (
            f"Telemetry from {prod} deployments in {env} environments indicates that the {comp} fails during "
            f"{ctx}. Operators observe {issue}, accompanied by diagnostic event `{code}` in the system journal."
        ),
        lambda comp, ctx, issue, prod, code, env: (
            f"When operating {prod} under {env} workloads, administrators report {issue}. Investigation of the "
            f"{comp} reveals a timing conflict involving {ctx}, which triggers fault code `{code}`."
        ),
        lambda comp, ctx, issue, prod, code, env: (
            f"On {prod}, the {comp} interacts directly with {ctx}. Under sustained {env} activity, this pathway "
            f"encounters {issue} and halts normal processing with status `{code}`."
        ),
        lambda comp, ctx, issue, prod, code, env: (
            f"Alert `{code}` is raised by {prod} whenever {ctx} is active across {env} topologies. "
            f"Specifically, the {comp} experiences {issue}, preventing downstream tasks from completing."
        ),
    ]

    resolution_patterns = [
        lambda fix, prod, code: (
            f"To remediate `{code}` on {prod}, {fix}. Verify stability by monitoring the subsystem metrics for 15 minutes after applying the change."
        ),
        lambda fix, prod, code: (
            f"Resolve this condition by performing the following maintenance action on {prod}: {fix}. No full hardware replacement is required."
        ),
        lambda fix, prod, code: (
            f"Engineering recommends that administrators {fix}. Once completed on {prod}, clear any latched `{code}` alerts from the health console."
        ),
    ]

    environments = [
        "high-availability production",
        "multi-tenant enterprise",
        "regional edge cluster",
        "hybrid cloud campus",
        "zero-trust financial",
        "automated CI/CD",
        "dense virtualization",
    ]

    articles: list[dict[str, Any]] = []
    article_num = 31

    domain_queues: dict[str, list[dict[str, Any]]] = {}
    for domain, spec in domain_specs.items():
        domain_list = []
        comps = spec["components"]
        fixes = spec["fixes"]
        products = spec["products"]
        for i in range(spec["count"]):
            comp_tuple = comps[i % len(comps)]
            fix_str = fixes[i % len(fixes)]
            prod = products[(i + (i // len(comps))) % len(products)]
            env = environments[(i * 3) % len(environments)]
            code = f"{spec['code_prefix']}_{spec['code_start'] + i}"

            pat_idx = i % len(narrative_patterns)
            res_idx = i % len(resolution_patterns)

            variant_num = (i // len(comps)) + 1
            comp_name, ctx_name, issue_desc = comp_tuple

            title_templates = [
                f"{comp_name.capitalize()} Fault During {ctx_name.capitalize()} ({code})",
                f"Resolving {code}: {prod} {comp_name.capitalize()} Disruption",
                f"Troubleshooting {comp_name.capitalize()} Anomaly on {prod} [Rev {variant_num}]",
                f"{prod} — {ctx_name.capitalize()} Triggers {code}",
            ]
            title = title_templates[i % len(title_templates)]

            symptom = narrative_patterns[pat_idx](comp_name, ctx_name, issue_desc, prod, code, env)
            resolution = resolution_patterns[res_idx](fix_str, prod, code)

            domain_list.append({
                "domain": domain,
                "title": title,
                "error_code": code,
                "product": prod,
                "trap_cluster": None,
                "symptom": symptom,
                "resolution": resolution,
            })
        domain_queues[domain] = domain_list

    domain_names = list(domain_specs.keys())
    while any(domain_queues[d] for d in domain_names):
        for d in domain_names:
            if domain_queues[d]:
                item = domain_queues[d].pop(0)
                item["id"] = f"KB-{article_num:03d}"
                articles.append(item)
                article_num += 1

    rng.shuffle(articles)
    for idx, art in enumerate(articles, start=31):
        art["id"] = f"KB-{idx:03d}"

    return articles


def get_independent_eval_queries() -> list[dict[str, Any]]:
    """
    42 independently written evaluation queries across 4 categories:
      - 14 exact_code queries (targeting specific error codes & firmware point releases)
      - 14 symptom queries (plain-English user descriptions with zero technical keyword overlap)
      - 12 mixed queries (every query combines plain-English symptom words + a partial code)
      - 2 unanswerable queries (plausible in-domain tech-support queries for nonexistent
        error codes / unreleased firmware versions that no KB article answers)
    """
    return [
        # =====================================================================
        # 14 EXACT_CODE QUERIES (Q-01 to Q-14)
        # =====================================================================
        {
            "id": "Q-01",
            "category": "exact_code",
            "query": "E_AUTH_501",
            "expected_id": "KB-001",
            "notes": "Exact code lookup inside sibling trap cluster TRAP-AUTH-50X (E_AUTH_501 vs 503 vs 509).",
        },
        {
            "id": "Q-02",
            "category": "exact_code",
            "query": "E_AUTH_503 AegisIAM Gateway",
            "expected_id": "KB-002",
            "notes": "Sibling trap code E_AUTH_503 on AegisIAM Gateway.",
        },
        {
            "id": "Q-03",
            "category": "exact_code",
            "query": "E_AUTH_509",
            "expected_id": "KB-003",
            "notes": "Sibling trap code E_AUTH_509.",
        },
        {
            "id": "Q-04",
            "category": "exact_code",
            "query": "ERR_SSL_102 NetCore EdgeProxy",
            "expected_id": "KB-004",
            "notes": "Exact TLS sibling code ERR_SSL_102.",
        },
        {
            "id": "Q-05",
            "category": "exact_code",
            "query": "ERR_SSL_108",
            "expected_id": "KB-005",
            "notes": "Sibling TLS trap code ERR_SSL_108.",
        },
        {
            "id": "Q-06",
            "category": "exact_code",
            "query": "Router-X1 v2.4.1 NET_BGP_410",
            "expected_id": "KB-007",
            "notes": "Firmware point-release trap: Router-X1 v2.4.1 + NET_BGP_410.",
        },
        {
            "id": "Q-07",
            "category": "exact_code",
            "query": "Router-X1 v2.4.9 NET_OSPF_419",
            "expected_id": "KB-009",
            "notes": "Firmware point-release trap targeting Router-X1 v2.4.9.",
        },
        {
            "id": "Q-08",
            "category": "exact_code",
            "query": "OmniSwitch-48P v5.1.2 SW_POE_212",
            "expected_id": "KB-010",
            "notes": "Switch firmware v5.1.2 + SW_POE_212 code lookup.",
        },
        {
            "id": "Q-09",
            "category": "exact_code",
            "query": "DB_LOCK_801 ChronosDB v6.3.0",
            "expected_id": "KB-012",
            "notes": "Sibling database lock code DB_LOCK_801.",
        },
        {
            "id": "Q-10",
            "category": "exact_code",
            "query": "DB_LOCK_809",
            "expected_id": "KB-014",
            "notes": "Sibling database lock code DB_LOCK_809.",
        },
        {
            "id": "Q-11",
            "category": "exact_code",
            "query": "CLI_ERR_901 NimbusCLI v2.9.0",
            "expected_id": "KB-015",
            "notes": "Sibling cloud CLI error code CLI_ERR_901.",
        },
        {
            "id": "Q-12",
            "category": "exact_code",
            "query": "CLI_ERR_907",
            "expected_id": "KB-017",
            "notes": "Sibling cloud CLI error code CLI_ERR_907.",
        },
        {
            "id": "Q-13",
            "category": "exact_code",
            "query": "DISP_EDID_301 ProDock",
            "expected_id": "KB-018",
            "notes": "Sibling display error code DISP_EDID_301.",
        },
        {
            "id": "Q-14",
            "category": "exact_code",
            "query": "DISP_PWR_309",
            "expected_id": "KB-020",
            "notes": "Sibling display error code DISP_PWR_309.",
        },

        # =====================================================================
        # 14 SYMPTOM QUERIES (Q-15 to Q-28)
        # Written in plain everyday user English with zero technical jargon overlap
        # =====================================================================
        {
            "id": "Q-15",
            "category": "symptom",
            "query": "how do I completely wipe my office router back to default out-of-the-box settings",
            "expected_id": "KB-022",
            "notes": "Colloquial 'wipe office router back to default out-of-the-box settings' vs formal 'NVRAM Factory Initialization'.",
        },
        {
            "id": "Q-16",
            "category": "symptom",
            "query": "external display keeps flashing dark and flickering brightness during games",
            "expected_id": "KB-023",
            "notes": "Colloquial 'flashing dark and flickering brightness' vs formal 'Vertical Blanking Interval Refresh Rate Desynchronization'.",
        },
        {
            "id": "Q-17",
            "category": "symptom",
            "query": "notebook sat unused in a closet for months and now it is totally dead with no lights",
            "expected_id": "KB-024",
            "notes": "Colloquial 'sat unused in a closet and now totally dead' vs formal 'Lithium-Ion Under-Voltage Lockout UVLO'.",
        },
        {
            "id": "Q-18",
            "category": "symptom",
            "query": "connected to hotel wifi on my phone yet the terms sign-in page never pops up",
            "expected_id": "KB-025",
            "notes": "Colloquial 'hotel wifi sign-in page never pops up' vs formal 'Captive Portal DNS Interceptor Loop'.",
        },
        {
            "id": "Q-19",
            "category": "symptom",
            "query": "copying massive video folders starts fast then drops to a crawl as the drive heats up",
            "expected_id": "KB-026",
            "notes": "Colloquial 'drops to a crawl as the drive heats up' vs 'NVMe Thermal Throttling & SLC Cache Saturation'.",
        },
        {
            "id": "Q-20",
            "category": "symptom",
            "query": "company single sign-on rejects employees when our server time is half a second off",
            "expected_id": "KB-027",
            "notes": "Plain description of server time half a second off vs 'SAML 2.0 NotBefore/NotOnOrAfter Validation Rejection'.",
        },
        {
            "id": "Q-21",
            "category": "symptom",
            "query": "containers keep getting kicked off the host server even with plenty of disk space left",
            "expected_id": "KB-028",
            "notes": "Plain description of containers kicked off server with free space vs 'Kubelet Ephemeral Storage Inode Exhaustion'.",
        },
        {
            "id": "Q-22",
            "category": "symptom",
            "query": "sql server suddenly locked up and blocks saving new rows to prevent data corruption",
            "expected_id": "KB-029",
            "notes": "Colloquial description of emergency write freeze vs 'PostgreSQL Transaction ID XID Wraparound'.",
        },
        {
            "id": "Q-23",
            "category": "symptom",
            "query": "high pitched buzzing squeal coming from inside the computer case when sitting idle",
            "expected_id": "KB-030",
            "notes": "Colloquial 'high pitched buzzing squeal when sitting idle' vs 'Acoustic Coil Whine From MLCC Piezoelectric Resonance'.",
        },
        {
            "id": "Q-24",
            "category": "symptom",
            "query": "third screen stays completely blank when linking multiple monitors together in a row",
            "expected_id": "KB-018",
            "notes": "Natural description of 3-monitor daisy-chain blackout without mentioning MST, EDID, or HBR3.",
        },
        {
            "id": "Q-25",
            "category": "symptom",
            "query": "screens plugged into my laptop hub go black briefly whenever the processor works hard",
            "expected_id": "KB-020",
            "notes": "Natural description of dock display brownout under load without mentioning PDO or VBUS.",
        },
        {
            "id": "Q-26",
            "category": "symptom",
            "query": "websites hang forever when loading over fiber internet even though basic ping works",
            "expected_id": "KB-008",
            "notes": "Plain description of fiber internet ping working while websites hang (KB-008 PPPoE MSS blackhole).",
        },
        {
            "id": "Q-27",
            "category": "symptom",
            "query": "security cameras and office wifi units stay powered off after restarting the network switch",
            "expected_id": "KB-010",
            "notes": "Plain description of cameras/wifi staying off after switch reboot (KB-010 PoE++ Class 6 denial).",
        },
        {
            "id": "Q-28",
            "category": "symptom",
            "query": "plug-in USB passkey dongle fails passwordless setup because its onboard memory slots are full",
            "expected_id": "KB-021",
            "notes": "Plain description of USB passkey memory slots full (KB-021 FIDO2 resident key overflow).",
        },

        # =====================================================================
        # 12 MIXED QUERIES (Q-29 to Q-40)
        # Every query combines plain-English symptom words with a partial code!
        # =====================================================================
        {
            "id": "Q-29",
            "category": "mixed",
            "query": "login keeps kicking users back to the sign-in screen after key change, auth 501",
            "expected_id": "KB-001",
            "notes": "Plain-English symptom ('login keeps kicking users back to sign-in screen') + partial code 'auth 501'.",
        },
        {
            "id": "Q-30",
            "category": "mixed",
            "query": "sign-in fails right after redirect because staging and prod IDs got mixed up, auth 503",
            "expected_id": "KB-002",
            "notes": "Plain-English symptom + partial code 'auth 503'.",
        },
        {
            "id": "Q-31",
            "category": "mixed",
            "query": "company proxy blocks external web apps when their certificate chain is incomplete, ssl 102",
            "expected_id": "KB-004",
            "notes": "Plain-English symptom + partial code 'ssl 102'.",
        },
        {
            "id": "Q-32",
            "category": "mixed",
            "query": "long streaming connection cuts off abruptly after sending a gigabyte of data, ssl 109",
            "expected_id": "KB-006",
            "notes": "Plain-English symptom + partial code 'ssl 109'.",
        },
        {
            "id": "Q-33",
            "category": "mixed",
            "query": "branch internet can ping out fine but web pages stall forever on v2.4.4",
            "expected_id": "KB-008",
            "notes": "Plain-English symptom + partial version code 'v2.4.4'.",
        },
        {
            "id": "Q-34",
            "category": "mixed",
            "query": "both paired uplink cables on the switch drop out at the exact same time, lacp 218",
            "expected_id": "KB-011",
            "notes": "Plain-English symptom + partial code 'lacp 218'.",
        },
        {
            "id": "Q-35",
            "category": "mixed",
            "query": "saving records pauses completely for several seconds every quarter hour, lock 801",
            "expected_id": "KB-012",
            "notes": "Plain-English symptom + partial code 'lock 801'.",
        },
        {
            "id": "Q-36",
            "category": "mixed",
            "query": "nightly batch import crashes when two workers insert child records at once, lock 804",
            "expected_id": "KB-013",
            "notes": "Plain-English symptom + partial code 'lock 804'.",
        },
        {
            "id": "Q-37",
            "category": "mixed",
            "query": "automated deployment pipeline stops halfway through after running for an hour, err 902",
            "expected_id": "KB-016",
            "notes": "Plain-English symptom + partial code 'err 902'.",
        },
        {
            "id": "Q-38",
            "category": "mixed",
            "query": "external TV screen goes blank whenever we open copy-protected streaming video, edid 305",
            "expected_id": "KB-019",
            "notes": "Plain-English symptom + partial code 'edid 305'.",
        },
        {
            "id": "Q-39",
            "category": "mixed",
            "query": "workstation battery drained completely in storage and refuses to wake up, uvlo 119",
            "expected_id": "KB-024",
            "notes": "Plain-English symptom + partial code 'uvlo 119'.",
        },
        {
            "id": "Q-40",
            "category": "mixed",
            "query": "managed database suddenly refuses to save any new records to prevent data loss, xid 990",
            "expected_id": "KB-029",
            "notes": "Plain-English symptom + partial code 'xid 990'.",
        },

        # =====================================================================
        # 2 UNANSWERABLE QUERIES (Q-41 to Q-42) — Plausible in-domain tech support
        # questions that NO article in the 250-article KB answers!
        # =====================================================================
        {
            "id": "Q-41",
            "category": "unanswerable",
            "query": "Router-X1 v3.9.0-beta2 quantum key distribution tunnel drops with error NET_QKD_999",
            "expected_id": None,
            "notes": "Plausible in-domain network support query referencing an unreleased firmware build (v3.9.0-beta2) and nonexistent error code (NET_QKD_999).",
        },
        {
            "id": "Q-42",
            "category": "unanswerable",
            "query": "AegisIAM Gateway v6.0.0 retinal biometric scanner fails liveness check with E_BIO_999",
            "expected_id": None,
            "notes": "Plausible in-domain IAM support query referencing an unreleased major version (v6.0.0) and nonexistent error code (E_BIO_999).",
        },
    ]


def word_tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9_.-]+", text.lower())


def longest_shared_word_sequence(query_text: str, doc_text: str) -> tuple[int, str]:
    q_words = word_tokens(query_text)
    d_words = word_tokens(doc_text)
    max_len = 0
    best_seq: list[str] = []
    for i in range(len(q_words)):
        for j in range(len(d_words)):
            k = 0
            while (
                i + k < len(q_words)
                and j + k < len(d_words)
                and q_words[i + k] == d_words[j + k]
            ):
                k += 1
            if k > max_len:
                max_len = k
                best_seq = q_words[i : i + k]
    return max_len, " ".join(best_seq)


def run_audits_and_reports(dataset: list[dict[str, Any]], queries: list[dict[str, Any]]) -> None:
    assert len(dataset) == 250, f"Expected 250 articles, got {len(dataset)}"
    assert len(queries) == 42, f"Expected 42 queries, got {len(queries)}"

    kb_by_id = {a["id"]: a for a in dataset}

    print("=" * 84)
    print("AUDIT 1: LEAK CHECK — LONGEST SHARED CONTIGUOUS WORD SEQUENCE (FLAGGING 4+ WORDS)")
    print("=" * 84)
    flagged_count = 0
    for q in queries:
        if q["expected_id"] is None:
            continue
        art = kb_by_id[q["expected_id"]]
        full_doc_text = f"{art['title']} {art['error_code']} {art['product']} {art['symptom']} {art['resolution']}"
        seq_len, seq_str = longest_shared_word_sequence(q["query"], full_doc_text)

        # Also check across all 250 articles for any 4+ word leak
        max_any_len = seq_len
        max_any_id = art["id"]
        max_any_str = seq_str
        for other in dataset:
            other_text = f"{other['title']} {other['error_code']} {other['product']} {other['symptom']} {other['resolution']}"
            o_len, o_str = longest_shared_word_sequence(q["query"], other_text)
            if o_len > max_any_len:
                max_any_len = o_len
                max_any_id = other["id"]
                max_any_str = o_str

        flag = " [FLAG >= 4 WORDS!]" if max_any_len >= 4 else " [OK]"
        if max_any_len >= 4:
            flagged_count += 1
        print(
            f"{q['id']} ({q['category']:<10} -> {q['expected_id']}): "
            f"target_len={seq_len} ('{seq_str}') | corpus_max={max_any_len} on {max_any_id} ('{max_any_str}'){flag}"
        )
    print(f"\nTotal queries flagged with 4+ contiguous shared words: {flagged_count} / 40")
    assert flagged_count == 0, f"Leak check failed: {flagged_count} queries have 4+ shared contiguous words!"

    print("\n" + "=" * 84)
    print("AUDIT 2: 5 SYMPTOM QUERIES VS. EXPECTED ARTICLE TITLE & SYMPTOM (KEYWORD OVERLAP)")
    print("=" * 84)
    symptom_queries = [q for q in queries if q["category"] == "symptom"][:5]
    for q in symptom_queries:
        art = kb_by_id[q["expected_id"]]
        q_content = {w for w in word_tokens(q["query"]) if w not in STOPWORDS}
        d_content = {w for w in word_tokens(f"{art['title']} {art['symptom']}") if w not in STOPWORDS}
        overlap = sorted(q_content & d_content)
        print(f"\n[{q['id']}] Expected: {art['id']} ({art['error_code']} | {art['product']})")
        print(f"  Query          : \"{q['query']}\"")
        print(f"  Article Title  : \"{art['title']}\"")
        print(f"  Article Symptom: \"{art['symptom']}\"")
        print(f"  Shared Content Words (Title+Symptom): {overlap if overlap else 'NONE (0 words)'}")


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    trap_articles = get_handwritten_trap_articles()
    filler_articles = generate_varied_filler_articles()
    dataset = trap_articles + filler_articles
    queries = get_independent_eval_queries()

    run_audits_and_reports(dataset, queries)

    dataset_path = base_dir / "dataset.json"
    queries_path = base_dir / "eval_queries.json"

    with open(dataset_path, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2, ensure_ascii=False)

    with open(queries_path, "w", encoding="utf-8") as f:
        json.dump(queries, f, indent=2, ensure_ascii=False)

    print(f"\nSuccessfully updated {dataset_path.name} and {queries_path.name}.")


if __name__ == "__main__":
    main()
