# NetPulse AI — Architecture Decision Records (ADRs)
**Document Version**: 1.0.0  
**Authoritative Reference**: `NetPulse_AI_Day_14-40_Engineering_Learning_Roadmap.docx`  
**Status**: Approved Baseline  

---

## Index of Decisions

- [ADR-001: Separation of Continuous Probing from Serverless Web Hosting](#adr-001-separation-of-continuous-probing-from-serverless-web-hosting)
- [ADR-002: Local Durable Queue (SQLite) for Edge Disconnect Resilience](#adr-002-local-durable-queue-sqlite-for-edge-disconnect-resilience)
- [ADR-003: Timing-Safe Ingestion Authentication & Batch Idempotency](#adr-003-timing-safe-ingestion-authentication--batch-idempotency)
- [ADR-004: Server-Only Data Access Layer & Zero Direct Anon Database Access](#adr-004-server-only-data-access-layer--zero-direct-anon-database-access)
- [ADR-005: Metric Nomenclature & Separation of RTT Variation from RFC 3550 RTP Jitter](#adr-005-metric-nomenclature--separation-of-rtt-variation-from-rfc-3550-rtp-jitter)
- [ADR-006: Server-Authoritative Device Status Evaluation](#adr-006-server-authoritative-device-status-evaluation)
- [ADR-007: Read-Only AI Diagnostic Copilot & Human-in-the-Loop Remediation](#adr-007-read-only-ai-diagnostic-copilot--human-in-the-loop-remediation)
- [ADR-008: Mandatory Environment Configuration Without Deprecated Fallbacks](#adr-008-mandatory-environment-configuration-without-deprecated-fallbacks)
- [ADR-009: Phased Protocol Expansion Strategy](#adr-009-phased-protocol-expansion-strategy)
- [Unresolved & Deferred Architectural Decisions](#unresolved--deferred-architectural-decisions)

---

### ADR-001: Separation of Continuous Probing from Serverless Web Hosting
- **Status**: Approved
- **Context**: Vercel Serverless functions run in ephemeral Node.js containers that scale down to zero when idle. They have no raw ICMP socket privileges, cannot access private enterprise LANs/homelabs, and impose strict request execution timeouts (15–60s).
- **Decision**: Continuous network probing is strictly decoupled from the web application. A dedicated Python daemon runs 24/7 on an always-on Linux host (or virtual machine / Raspberry Pi) inside the customer network. The Vercel application acts purely as an ingestion endpoint (`/api/ingest/v1/*`) and web presentation layer.
- **Consequences**:
  - *Positive*: Unbounded continuous probing without serverless timeout limits; native ICMP socket privileges; private network accessibility.
  - *Negative*: Requires managing a standalone edge Python process (managed via systemd or container).

---

### ADR-002: Local Durable Queue (SQLite) for Edge Disconnect Resilience
- **Status**: Approved
- **Context**: Edge-to-cloud network links inevitably experience transient drops, ISP outages, or cloud cold starts. Buffering samples in memory risks losing operational telemetry during power drops or process restarts.
- **Decision**: The edge Python collector implements a persistence-first write pattern using a local SQLite database (`spool.db`). Every completed probe burst is written to disk before network upload. The collector drains pending batches over HTTPS and deletes **only** sample IDs explicitly acknowledged by the server.
- **Consequences**:
  - *Positive*: Zero telemetry loss across 10+ minute WAN blackouts; clean restart recovery.
  - *Negative*: Introduces minor local disk I/O overhead on the collector host (mitigated by SQLite WAL mode).

---

### ADR-003: Timing-Safe Ingestion Authentication & Batch Idempotency
- **Status**: Approved
- **Context**: Ingestion APIs exposed to the internet can be attacked via secret timing side-channels, and network retransmissions can inject duplicate historical sample rows into the database.
- **Decision**:
  1. Ingestion authentication compares the incoming `x-ingest-key` header against `process.env.INGEST_SECRET` using Node.js `crypto.timingSafeEqual`.
  2. `telemetry_samples` enforces a compound unique constraint: `unique(collector_id, device_id, observed_at, sequence_no)`. Retried batches execute `ON CONFLICT DO NOTHING`.
- **Consequences**:
  - *Positive*: Complete defense against timing attacks and idempotent deduplication of replayed packets.
  - *Negative*: Requires collectors to attach deterministic sequence numbers and observation timestamps.

---

### ADR-004: Server-Only Data Access Layer & Zero Direct Anon Database Access
- **Status**: Approved
- **Context**: Exposing Supabase anonymous keys to the browser with public SELECT RLS policies allows anonymous users to inspect network management IPs and internal switch hostnames, creating an information disclosure vulnerability.
- **Decision**:
  1. Supabase RLS is configured to deny all direct anonymous access (`for select using (false)` or no anon policy).
  2. The frontend browser never interacts with Supabase directly. All database access routes through `src/lib/dal.ts`, which is guarded with `import 'server-only'`.
  3. The server determines identity: unauthenticated requests receive synthetic demo data (`10.0.0.x`); authenticated operators receive real enterprise telemetry.
- **Consequences**:
  - *Positive*: Private network topology is 100% shielded from public observation; zero secrets bundled into client JavaScript.
  - *Negative*: Every client interaction requires passing through a Next.js Server Component or Route Handler.

---

### ADR-005: Metric Nomenclature & Separation of RTT Variation from RFC 3550 RTP Jitter
- **Status**: Approved
- **Context**: RFC 3550 defines interarrival jitter for continuous real-time audio/video RTP streams. Applying RFC 3550 formulas to discrete ICMP ping bursts is a domain categorization error.
- **Decision**:
  1. The metric is explicitly named `rtt_variation_ms`, defined as the mean absolute difference between consecutive probe samples:
     $$\text{rtt\_variation\_ms} = \frac{1}{N-1} \sum_{i=1}^{N-1} |RTT_{i+1} - RTT_i|$$
  2. Documented calculations and Vitest test suites reference `rtt_variation_ms` and do not claim RFC 3550 compliance.
- **Consequences**:
  - *Positive*: Mathematical and domain precision; prevents false engineering claims.
  - *Negative*: None.

---

### ADR-006: Server-Authoritative Device Status Evaluation
- **Status**: Approved
- **Context**: Relying on edge collectors to calculate and submit device health status (`online`, `degraded`, `offline`) risks split-brain status definitions across different collector versions and vendor agents.
- **Decision**: Collectors report raw probe telemetry (sent count, received count, RTT array). The server evaluates device status authoritatively using deterministic thresholds and rolling hysteresis:
  - *Online*: $\le 1\%$ packet loss and normal latency.
  - *Degraded*: $2\%$ to $99\%$ packet loss, or latency exceeding thresholds.
  - *Offline*: $100\%$ packet loss sustained across probe bursts.
  - *Stale*: No sample received within $3 \times$ probe interval.
- **Consequences**:
  - *Positive*: Centralized policy management; edge collectors remain lightweight and decoupled.
  - *Negative*: Additional metric normalization compute on the ingestion server (sub-millisecond for batches of 50).

---

### ADR-007: Read-Only AI Diagnostic Copilot & Human-in-the-Loop Remediation
- **Status**: Approved
- **Context**: Permitting an LLM to autonomously execute CLI commands or mutate switch configurations introduces catastrophic risk (accidental interface shutdown, routing table corruption, hallucinated commands).
- **Decision**:
  1. The Gemini Copilot is strictly a **Read-Only Intelligence Assistant**. It possesses zero SSH execution engines and zero write access to network hardware.
  2. Diagnostic troubleshooting proposals render as formatted **Remediation Cards** with a "Copy to Clipboard" button for human review.
  3. Commands are validated against an explicit read-only regex whitelist (e.g. `^show (interfaces|ip bgp summary|version).*$`). Metacharacters (`|`, `>`, `;`, `&&`) and destructive words (`reload`, `write erase`) are rejected.
- **Consequences**:
  - *Positive*: Absolute operational safety; zero risk of autonomous configuration corruption.
  - *Negative*: Requires human intervention to execute proposed commands on terminals.

---

### ADR-008: Mandatory Environment Configuration Without Deprecated Fallbacks
- **Status**: Approved
- **Context**: Hardcoding fallback model names (e.g. `|| 'gemini-2.0-flash'`) leads to silent production breakage when providers deprecate older model versions.
- **Decision**: `process.env.GEMINI_MODEL` is strictly mandatory. If missing or undefined at startup, the server throws an immediate, actionable configuration exception: `"Missing GEMINI_MODEL. Please check Google AI Studio for active model identifiers."`
- **Consequences**:
  - *Positive*: Guarantees model freshness; prevents runtime 404 deprecation crashes.
  - *Negative*: Requires operators to populate `GEMINI_MODEL` in `.env.local` and Vercel settings.

---

### ADR-009: Phased Protocol Expansion Strategy
- **Status**: Approved
- **Context**: Attempting to implement ICMP, SNMP, BGP, sFlow, and gNMI simultaneously within 40 days leads to architectural collapse and superficial implementations.
- **Decision**: A phased rollout strategy:
  - **Phase 1 (Days 14–40)**: Multi-probe ICMP MVP across 200–300 devices, SQLite durable queue, Next.js dashboard, read-only Gemini Copilot.
  - **Phase 2 (Days 41–70)**: SNMP interface counters, optical transceiver power, CPU/memory metrics.
  - **Phase 3 (Days 71–90)**: BGP peer status monitoring and route flap detection.
  - **Phase 4 (Days 91–110)**: sFlow traffic conversation capture and top talkers.
  - **Phase 5 (Days 111+)**: gNMI streaming telemetry subscriptions.
- **Consequences**:
  - *Positive*: Delivers a dependable, verifiable ICMP monitoring platform on Day 40 without scope creep.
  - *Negative*: Advanced protocol metrics are deferred to subsequent development phases.

---

## Unresolved & Deferred Architectural Decisions

The following items are deliberately deferred until post-Day-40 operational data is gathered:
1. **Time-Series Partitioning Strategy**: Once `telemetry_samples` exceeds 5 million rows, evaluate PostgreSQL native declarative table partitioning (monthly partitions) versus TimescaleDB hypertable extension.
2. **Collector Authentication Hardening**: Evaluate mutual TLS (mTLS) or per-request HMAC-SHA256 signatures for zero-trust enterprise multi-tenant deployments.
3. **High-Velocity Flow Storage**: Determine whether sFlow / NetFlow ingestion (Phase 4) requires a dedicated columnar store (e.g. ClickHouse) or if aggregated rollups in PostgreSQL suffice.

---
*Signed off — NetPulse AI Architecture Review Board (2026).*
