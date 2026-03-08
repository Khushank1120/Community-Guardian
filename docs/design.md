# Community Guardian - Design Documentation

## Problem Understanding
People receive fragmented safety signals from social feeds, neighborhood apps, and scattered news sources. This creates two failure modes: alert fatigue and underreaction. The product goal is to convert noisy inputs into calm, actionable, and local guidance with explicit trust signals.

## Scope and Rationale
The prototype is a Java CLI by design.
- Reason: the evaluation prioritizes engineering behavior, architecture, correctness, and tradeoff quality over UI polish.
- Result: development time was invested in core flow completeness, fallback reliability, validation, security controls and documentation rather than frontend work.

## Target Users
- Neighborhood members tracking local safety patterns.
- Remote workers exposed to phishing/scam waves.
- Elderly users needing simplified, non-panic guidance.

## Core User Flows
1. User logs in (or signs up with default location).
2. User creates incident report with input validation.
3. User/reviewer views feeds with filters and search.
4. Reviewer processes review queue and updates verification/status.
5. User/reviewer generates digest by period and location.
6. Users share and read encrypted safe-circle updates with access control.

## Architecture (Layered)
### CLI Layer
- `CommunityGuardianApp`: command dispatch, argument parsing, JSON/pretty output.
- `TerminalWorkbench`: role-based interactive menus and guided flows.
- `OutputFormatter`: presentation formatting for terminal output.

### Domain/Service Layer
- `DigestService`: AI digest generation with deterministic fallback.
- `ConfidenceService`: rule-first confidence scoring + optional AI adjustment.
- `CategorizationService`: optional AI categorization with rule fallback.
- `ReportInsightsService`: clustering summaries, scope labeling, checklists.
- `SafeCircleService`: circle membership rules and encrypted status updates.
- `AuthorizationService`: owner/manager guardrails for member administration.

### Security/Cross-Cutting Layer
- `AuthService`: encrypted users DB read/write, signup policy, login, lockout.
- `KeyService`: key retrieval and key-ring version selection from env.
- `IntegrityService`: HMAC signatures for tamper detection on CSV stores.
- `AuditService`: security and moderation event logging.

### Data Layer
- `IncidentRepository`: CSV persistence, filtering/search, expiry, cluster keying, encrypted location handling.
- `Incident` model: normalized data contract for read/write and rendering.

## Data Model and Lifecycle
- Data source is synthetic CSV only.
- Incident records include severity, verification status, confidence, review flag, expiry, and cluster identifier.
- Expiry policy defaults by severity:
  - `high`: 30 days
  - `medium`: 14 days
  - `low`: 7 days
- Expired incidents are hidden by default and can be pruned.

## AI Usage and Fallback Design
### AI Functions
- Digest summarization into calm community updates.
- Optional confidence adjustment at incident creation.
- Optional categorization when `category=auto`.

### Fallback Rules
- If AI key is missing, API fails, quota is exceeded, or parse fails:
  - digest switches to deterministic rule summary,
  - confidence remains rule-derived,
  - categorization falls back to keyword/rule classification.

### Why Rule-First for Trust Scoring
- Predictable behavior for reviewers.
- Safer failure modes under outage/quota pressure.
- Better explainability for an assessment context.
- Note: digest summarization and `category=auto` still attempt AI first, then fall back to rules when needed.

## Noise-to-Signal Strategy
- Confidence score combines source type, verification, details quality, severity weighting, and validated corroboration.
- Low-confidence unverified incidents are routed to review queue.
- Cluster collapse reduces repeated feed entries.
- Scope labels communicate certainty:
  - `widespread`,
  - `local-emerging`,
  - `local-unverified`.

## Security Design
### Secrets and Keys
- No API keys committed.
- `.env` provides runtime keys; `.env.example` documents required variables.
- Key-ring format supports rotation (`v1:...;v2:...`) with active version selection.

### Data Protection
- `users.csv` encrypted at rest (AES-GCM envelope).
- Incident `location` encrypted at field level.
- Safe-circle messages encrypted at rest.

### Integrity and Tamper Detection
- CSV datasets have HMAC signature sidecars (`.sig`).
- Reads verify signatures when present before trusting file contents.

### Authentication and Authorization
- PBKDF2 password hashing with per-user salt.
- Account lockout after repeated failed logins.
- Role-based menus (`user`, `reviewer`).
- Circle ownership and delegated member-management permissions.

### Auditability
- Authentication, account, incident, and circle actions are logged to `audit.log`.

## Responsible AI Considerations
- Synthetic data only; no live scraping.
- User profile credentials are not sent to AI.
- Unverified signals are clearly separated from verified updates.
- AI outputs are never single points of failure due to deterministic fallback paths.

## Requirement Coverage Mapping
1. Core flow: create/view/update + filter/search + digest.
2. AI + fallback: summarize/categorize/confidence with rule fallback.
3. Basic quality: strict validation, clear errors, automated tests.
4. Data safety: synthetic CSV bundled in repo.
5. Security: env-based secrets, encryption, integrity checks, auth controls.

## Tradeoffs
- CSV chosen for speed and simplicity; not ideal for concurrent writes.
- Lightweight JSON extraction keeps dependencies minimal; less robust than schema-based parsing.
- Shared-passphrase safe-circle model enables quick E2E demo; not full production key lifecycle.
- Deterministic clustering is fast but misses semantic near-duplicates.

## Future Enhancements
- Personalized calm-alert profiles: opt-in anxiety-aware notification tuning from user preferences (frequency, severity tolerance, quiet hours).
- Scheduled digests and multi-channel delivery (email/SMS/push) with strict anti-spam pacing controls.
- Semantic clustering/duplication detection via embeddings for better near-duplicate merging.
- Multi-model verification for high-risk incidents (consensus thresholds, cost controls, and fallback behavior).
- Source reputation scoring with historical precision, decay, and reviewer feedback integration.
- Geofencing and distance-weighted relevance ranking beyond string-only location matching.
- Anomaly detection for sudden local spikes and coordinated scam campaigns.
- SQL-backed storage with transactions, indexing, backup/restore, and migration/versioning.
- Stronger auth stack: JWT/session model, optional MFA, and policy-engine-based authorization.
- Full key lifecycle management: key IDs per record, rotation automation, and KMS/vault integration.
- Per-member safe-circle key exchange, rotation, and revocation.
- Reviewer SLA queue, assignment, and escalation logic.
- Immutable audit exports and operations dashboarding with logs/metrics/traces/alerts.
- REST API surface for web/mobile clients using the same domain services.
