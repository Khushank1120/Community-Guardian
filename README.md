# Community Guardian (Java CLI)

Candidate Name: Khushank Mistry
Scenario Chosen: Community Safety & Digital Wellness  
Estimated Time Spent: 4-6 hours  

## Quick Start

### Prerequisites
- Java 17+
- macOS/Linux shell

### Run Commands
```bash
git clone <your-repo-url>
cd Community-Guardian
cp .env.example .env
set -a
source .env
set +a

mkdir -p out
javac -d out $(find src/main/java src/test/java -name "*.java")

# Initialize synthetic incidents DB (required once or when resetting data)
java -cp out com.communityguardian.cli.CommunityGuardianApp init-db --db data/incidents_db.csv

# Start interactive terminal app (role-based login + menu).
# It auto-initializes users DB if missing.
java -cp out com.communityguardian.cli.CommunityGuardianApp start --db data/incidents_db.csv
```

### App Flow (Terminal)
- Launch app with `start`.
- Login as demo accounts or sign up a new user with the default location.
- `user` flow:
- Create an incident report.
- View the signal feed with filters.
- Generate digest (defaults to user location if blank; use `ALL` for all locations).
- Open circle settings to create circle and manage members.
- Share and view safe-circle updates.
- `reviewer` flow:
- View review queue.
- Verify/update incidents.
- View clusters and prune expired incidents.

### Test Commands
```bash
java -cp out com.communityguardian.CommunityGuardianTests
```
This runner executes service-level tests for:
- `ConfidenceService`
- `DigestService`
- `IncidentRepository`
- `ReportInsightsService`
- `SafeCircleService`
- `OutputFormatter`
- `AuthService`
- `CategorizationService`
plus integration tests for end-to-end CLI behavior.

Security note: `data/users.csv` is stored encrypted at rest (AES-GCM envelope).
Password note: user passwords are salted and hashed with `PBKDF2-HMAC-SHA256` (legacy salted SHA-256 hashes are auto-upgraded on successful login).
Data privacy note: incident `location` is encrypted at field level at rest and decrypted in-memory using `INCIDENT_DATA_KEY`.
Trust-safety note: contradiction gate can force `needsReview=true` when high-trust user claims conflict with low AI confidence.

## AI Disclosure
- Did you use an AI assistant (Copilot, ChatGPT, etc.)? Yes - gpt-4.1-mini, gpt-5.3-codex and claude-opus-4.6 (mainly to compare different implementation ideas and perspectives while designing the solution)
- How did you verify the suggestions?
  - Compiled after each change.
  - Ran CLI smoke flows (`init-db`, `create`, `list`, `update`, `digest`).
- Added and executed focused tests for happy path and edge cases.
- Give one example of a suggestion you rejected or changed:
  - Initially attempted a single-provider confidence mechanism. Changed to rule-first confidence with optional AI adjustment so the app remains deterministic when AI fails.

## Tradeoffs & Prioritization
- What did you cut to stay within the 4–6 hour limit?
  - No web UI; focused effort on core CLI flow, validation, and testability.
  - No live scraping/ingestion from social/news APIs; used synthetic seeded data to keep behavior deterministic and policy-safe.
  - No background scheduler/notification transport; digest is on-demand in V1.
  - No per-member cryptographic key exchange for circles; used passphrase-based encryption to ship an end-to-end secure sharing flow quickly.
  - No database migration to SQL in V1; CSV chosen for low setup cost and faster iteration during the time box.
- Why these choices were made:
  - Priority is to satisfy: requirement completeness, fallback reliability, security hygiene, and clear technical reasoning.
  - CLI-first reduced UI overhead and let time go into architecture, documentation, safeguards, and test coverage.
  - Rule-first decisioning (confidence/review) ensures predictable behavior even when AI is unavailable, rate-limited, or incorrect.
  - Security controls were implemented early (encryption, integrity signatures, lockout, audit logs) to avoid retrofitting later.
- What would you build next if you had more time?
  - Personalized calm-alert profiles: generate an anxiety-aware notification profile from explicit user preferences (opt-in), then throttle cadence and severity to reduce alert fatigue.
  - Scheduled and channel-aware delivery: daily/weekly digests, quiet hours, and user-selectable channels (email/SMS/push).
  - Semantic/embedding-based deduplication so near-identical incidents cluster together even with wording differences.
  - Source reputation scoring with historical accuracy, decay, and reviewer feedback loops.
  - Multi-model verification for high-risk reports (cross-check/consensus with budget and confidence guardrails).
  - SQL persistence with transactional writes, indexing, backup/restore, and migration/version tooling.
  - Stronger security architecture: JWT/session tokens, optional MFA, centralized policy engine, and per-member safe-circle key exchange.
  - Full key lifecycle: key IDs per record, rotation tooling, and vault/KMS-backed secret management.
  - Geofencing and distance-based relevance ranking instead of location string matching only.
  - Reviewer triage enhancements: queue scoring, SLA timers, assignment/escalation workflow.
  - Anomaly detection for sudden local threat spikes and coordinated scam campaigns.
  - Immutable audit exports, security dashboarding, and broader observability (logs/metrics/traces/alerts).
  - REST API layer so web/mobile clients can integrate with the same backend logic.
- Known limitations:
  - User account lifecycle is basic in V1: limited profile settings, no forgot-password/reset flow, and no self-serve account deletion. 
  - AI response parsing is lightweight string extraction; robust schema validation is deferred.
  - CSV is not concurrency-safe and is vulnerable to operational issues under parallel writes.
  - Current clustering is string/key-based, so semantically similar incidents may split into separate clusters.
  - Confidence scoring is heuristic and needs calibration against labeled real-world incident data.
  - Safe-circle encryption uses a shared passphrase model; production systems should use per-member cryptographic controls.
  - Runtime security depends on correct key loading in the environment; missing keys cause hard failures by design.

## Demo Video
- My 5–7 minute video link (YouTube): `https://youtu.be/P1wDjkkaBbw`

## Requirement Coverage
1. Core flow: create + list/search/filter + update + digest (+ signal feed/cluster views).
2. AI plus fallback: OpenAI digest + deterministic fallback; optional AI confidence adjustment and optional `category=auto` categorization, both with rule fallback; contradiction gate can force review on low-AI/high-trust conflicts.
3. Basic quality: validation, clear errors, and service-level + integration tests (happy path + multiple edge cases).
4. Data safety: synthetic sample CSV included (`data/sample_incidents.csv`).
5. Security: no committed keys; `.env.example` provided and `.env` ignored.

## Interactive Login Notes
- Two roles are supported:
  - `user`: create/view incidents, digest, checklist, safe-circle updates
  - `reviewer`: review queue, verify/update incidents, clusters, prune expired
- During signup, each account stores a default location.
- In the terminal digest flow:
  - blank location input ⇒ uses user's default location,
  - `ALL` => includes all locations,
  - any other value ⇒ uses that specific location.
- On first `start`, default demo accounts are auto-created in `data/users.csv` (encrypted at rest):
  - `demo_user / UserDemo@1234`
  - `demo_reviewer / ReviewDemo@1234`
- Set security keys in `.env` (required): `USERS_DB_KEY`, `INCIDENT_DATA_KEY`, `DATA_INTEGRITY_KEY`.
- Optional trust controls in `.env`: `CONFIDENCE_REVIEW_THRESHOLD`, `AI_CONTRADICTION_GATE_ENABLED`, `AI_CONTRADICTION_LOW_THRESHOLD`.
