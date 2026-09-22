# CyberShield 32-Week Roadmap (High-Level)

Summary: 32 weeks broken into 8 x 4-week sprints. Deliverables include PoC, mobile agent, UI, ML engine, testing, and release.

Sprint 0 (Week 1) — PoC & Validation
- Deliver PoC Linux detector (cybershield-poc). Single-pass test and continuous monitor.
- Validate detection heuristics, entropy thresholds, and tuning.

Sprint 1 (Weeks 2-5) — Mobile Scaffold & Native Services
- Create React Native skeleton and Android Kotlin module.
- Define native telemetry APIs and IPC (AIDL/bridge).
- Deliverables: `mobile/react-native-app`, `mobile/android` skeletons.

Sprint 2 (Weeks 6-9) — File Monitoring Native Agent
- Implement Kotlin native file-monitoring service for Android (FileObserver + /proc hooks).
- Provide secure IPC to RN UI and local storage schema.

Sprint 3 (Weeks 10-13) — Behavioral Engine Core
- Implement behavior scoring engine core (local rules, thresholds, process trees).
- Create local SQLite threat DB schema and ingestion pipeline.

Sprint 4 (Weeks 14-17) — Ransomware & Memory Protections
- Implement entropy/chi-square ensemble, mass-mod detection, and sandboxing hooks.
- Prototype memory protection ideas where platform allows.

Sprint 5 (Weeks 18-21) — ML Engine Prototype
- Feature extraction pipeline and rule generalization prototype.
- Validation against labelled samples and false-positive mitigation.

Sprint 6 (Weeks 22-25) — UI & Forensics Dashboard
- Implement React Native components: Dashboard, Process Tree, Network Graph, Forensics viewer.
- Add LLM-based local explainers for alerts (on-device).

Sprint 7 (Weeks 26-29) — Testing, CI, and Hardening
- Add unit/integration tests, CI pipelines for Android and RN, automated security checks.

Sprint 8 (Weeks 30-32) — Release & Documentation
- Final testing, packaging, privacy audit, user docs, and release artifacts.

Milestones & Owners
- M1 (W1): PoC complete — Owner: Core Research
- M2 (W5): Mobile scaffold — Owner: Mobile Team
- M3 (W13): Behavior engine core — Owner: Backend Team
- M4 (W21): ML prototype — Owner: Data Science
- M5 (W29): UI + CI — Owner: Frontend/DevOps
- M6 (W32): Release — Owner: Product

Risk & Mitigations
- FP risk: Add conservative thresholds and sandbox verification.
- Platform limitations: Use platform-specific modules (eBPF, ETW, NEFilter) as adapters.
