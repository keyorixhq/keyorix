# CRA reporting process: actively exploited vulnerabilities and severe incidents

**Status: DRAFT for Andrei's review and signature. Not yet adopted.**
Owner: Andrei Beshkov. Review: before the first designated release, after every real
report, and at least once a year.

This document is the operating procedure for the reporting duty that the EU Cyber
Resilience Act (Regulation (EU) 2024/2847, "CRA") puts on a manufacturer. It sits
between three existing documents and does not contradict them:

- [`SECURITY.md`](../../SECURITY.md) is the public policy and stays canonical for
  researcher reports, the 48 h / 7 day / 90 day commitments and the support table.
- [`incident-response-plan.md`](incident-response-plan.md) (the "IR plan") owns roles,
  severity, the first-hour checklist and evidence handling. Its section 7 lists the CRA
  clock as a fact to confirm; this document is the detailed CRA row of that table.
- [`SUPPORT.md`](../../SUPPORT.md) and ADR-067 / ADR-104 own which versions are
  supported. Nothing here changes a support period, and the 90-day remediation
  ceiling in ADR-104 is a different commitment to a different audience (customers), not
  a regulator deadline. Do not read the day-counts below as the same thing.

## How to read the verification markers

- **[VERIFY]** means the statement was not confirmed against the regulation text.
  The official text on EUR-Lex could not be retrieved when this draft was written (the
  fetch returned an empty page, and EUR-Lex is not reachable from the drafting
  environment). Every [VERIFY] must be checked against the Official Journal text
  (<https://eur-lex.europa.eu/eli/reg/2024/2847/oj>) before signature.
- **[DECISION]** means a choice only Andrei can make.
- **Confirmed (Commission page)** means confirmed from the European Commission's own CRA
  pages (<https://digital-strategy.ec.europa.eu/en/policies/cra-reporting> and
  <https://digital-strategy.ec.europa.eu/en/policies/cra-summary>, fetched 2026-10-22).
  Those pages are official summaries, not the regulation text, and they say so
  themselves. Counsel should still confirm against the text.

## 1. What the obligation says, in plain words

| Item | Statement | Status |
|---|---|---|
| Who | The manufacturer of a product with digital elements | Confirmed (Commission page) |
| Applies from | **11 September 2026** (reporting obligations; the main CRA obligations apply later, from 11 December 2027) | Confirmed (Commission page): "reporting obligations set out in Article 14 apply from 11 September 2026". Article 71 as the source of the date: [VERIFY] |
| Which products | All products with digital elements made available on the Union market, including ones placed on the market before that date | Confirmed (Commission page). How this applies to pre-1.0 tags: [DECISION] 3 below |
| Trigger 1 | An **actively exploited vulnerability** in the product (a vulnerability that a malicious actor has exploited in a system without the system owner's permission) | Concept confirmed; exact Article 3 definition wording: [VERIFY] |
| Trigger 2 | A **severe incident having an impact on the security of the product** | Concept confirmed; exact Article 3 definition wording: [VERIFY] |
| Early warning | Within **24 hours** of becoming aware | Confirmed (Commission page) |
| Notification | Within **72 hours** of becoming aware | Confirmed (Commission page) |
| Final report, exploited vulnerability | No later than **14 days after a corrective or mitigating measure is available** (not 14 days after awareness) | Confirmed (Commission page) |
| Final report, severe incident | Within **one month of the 72-hour notification** | Confirmed (Commission page) |
| Where | The **single reporting platform** (SRP) run by ENISA, operational from 11 September 2026. One submission reaches the CSIRT of the Member State of the manufacturer's main establishment and ENISA at the same time | Confirmed (Commission page) |
| Article numbers | Reporting is Article 14; the platform is Article 16 | Confirmed (Commission page). Paragraph numbers inside Article 14, and the Article 3 definitions: [VERIFY] |
| Informing users | The manufacturer must also tell affected users, and where appropriate all users, about the vulnerability or incident and any mitigation they can apply | Concept recalled, not confirmed: [VERIFY] Article 14 paragraph |
| Content of each report | What each stage must contain (nature of the exploit, affected product versions, corrective measures, sensitivity, etc.) | [VERIFY] against Article 14 and the SRP form; the templates in section 6 are a working set, not a legal minimum |
| Support period | At least five years unless the product is expected to be in use for less, with security updates available for ten years or the rest of the support period, whichever is longer | Already stated in `SUPPORT.md` as Article 13(8); [VERIFY] the paragraph and the ten-year rule |

Things that do **not** start the 24 h clock on their own (recorded so the founder does
not over-report in a panic, and not under-report either): a scanner finding with no
exploit; a published CVE for a dependency that is not reachable in Keyorix; a
coordinated-disclosure report with no evidence of exploitation. These become reportable
if there is evidence of active exploitation. [VERIFY] this reading with counsel; the
Commission page we relied on is a summary. When unsure, treat as reportable (section 4).

## 2. Is Keyorix in scope? How that is decided: [DECISION] items

This draft does not decide the product's CRA status. The facts available in the repo:

- Keyorix SL (Valencia, Spain) is the developer. The product is an on-premise
  secrets manager, self-hosted, with no telemetry. It is dual licensed (AGPL-3.0 and a
  commercial licence) and sold commercially.
- `SECURITY.md` and `SUPPORT.md` say pre-1.0 tags are development releases, not placed
  on the market, with no declared support period or Declaration of Conformity.
- `SECURITY.md` also says "we operate under the EU Cyber Resilience Act reporting regime
  for actively exploited vulnerabilities", with a `CONFIRM WITH COUNSEL` comment: these
  two statements need to be reconciled (decision 3).

**[DECISION] 1 — Manufacturer status.** Keyorix SL very probably is a "manufacturer" of
a "product with digital elements" for the commercially distributed server, CLI and
container images. Open-source software supplied in the course of a commercial activity
is generally not exempt; a free, non-commercial project would be treated differently
(steward regime). Andrei and counsel decide and record: *manufacturer / open-source
steward / out of scope*. Recommendation: plan as **manufacturer**, because the
commercial licence and paid support are a commercial activity. [VERIFY] the exemption
wording in the regulation (recitals and Article 3 on commercial activity and on
open-source software stewards).

**[DECISION] 2 — Product class.** Whether the product is in the "default" category, or
an **important product** (class I or II in Annex III), or **critical** (Annex IV). A
secrets manager is close to password managers and identity/access-management software,
which may be listed in Annex III. This was not confirmed; the Commission summary does
not list the Annex III items, and the technical descriptions of the categories are in
Commission Implementing Regulation (EU) 2025/2392 (<http://data.europa.eu/eli/reg_impl/2025/2392/oj>),
which was not read for this draft. [VERIFY] the Annex III item list and the
implementing-regulation descriptions, then record the class. The class changes the
conformity-assessment route (self-assessment versus third-party), **not** the reporting
duty in this document, which applies to all manufacturers [VERIFY]. Recommendation:
assume "likely important" for planning the 1.0 conformity route until counsel says
otherwise.

**[DECISION] 3 — Pre-1.0 tags and the reporting duty.** The Commission page says the
reporting duty covers products made available on the Union market. `SUPPORT.md` says
pre-1.0 tags are not offered as products placed on the market, while the AGPL source and
binaries are public and downloadable from GitHub, and a commercial licence is sold.
Options: (a) take the conservative position that a public release that anyone in the EU
can download is "made available" and **report from 11 Sep 2026 regardless of tag**;
(b) rely on the "development release" position and report only for designated releases
from 1.0. Recommendation: **(a)**: reporting costs a few hours when it happens, a
missed duty is a regulatory matter, and `SECURITY.md` already tells the public we report.
Whichever is chosen, `SECURITY.md` line 79-82 and `SUPPORT.md` § Current status must
say the same thing. Do not edit them in this PR; the proposed wording is in the session
report. Counsel to confirm.

**[DECISION] 4 — Main establishment / CSIRT.** The CSIRT receiving the report is the
one of the Member State of the manufacturer's main establishment, so for Keyorix SL
this is Spain. Spain's designated coordinator CSIRT for the CRA, and whether the SRP
requires manufacturer registration before the first report, are **[VERIFY]**. Action:
register on the SRP **before** the first incident so the 24 h clock is not spent on
account setup (section 3).

**[DECISION] 5 — Backup for the founder.** The IR plan names cofounders as deputies
with placeholders. Decide who can file on the SRP if Andrei is unreachable, and give
them access in advance.

## 3. Who does what

Roles are the IR plan's (section 1). For a CRA report:

| Role | Does | Who |
|---|---|---|
| **Incident Commander (IC)** | Decides "reportable or not", signs every submission, owns the clock | Andrei Beshkov (founder) |
| **Technical lead** | Establishes facts: affected versions, evidence of exploitation, fix or mitigation status | Andrei, or whoever knows the area |
| **Filer** | Enters reports on the SRP | Andrei; deputy per [DECISION] 5 |
| **Scribe** | Keeps the UTC timeline | Anyone who is not the technical lead; if alone, a plain-text file appended as you go |
| **Counsel** | Confirms wording on request | External counsel `[firm, contact: CONFIRM]` |

Because the team is one founder, the two-person rule of the IR plan (confirm before
notifying a regulator) applies **only if a second person can be reached within the
time left on the clock**. The clock wins: if nobody can be reached, the IC files and
records why. A late report is worse than an unreviewed one; a correction can be sent
afterwards.

**Contact channel for intake.** Anything that may be an actively exploited
vulnerability or severe incident arrives through the channels in `SECURITY.md`:
GitHub private vulnerability reporting, or **security@keyorix.com** (the only security
address). The same mailbox is the product's single point of contact for vulnerability
reports. Reporting a vulnerability is also possible from customers and pilots: tell them
to use the same address. Phone and out-of-band contact details live in the contact
sheet outside this repository (the IR plan names it); the SRP credentials and the
contact sheet must be reachable **without** the possibly-compromised systems.

**SRP access.** `[SRP registration status, account owner, deputy account: CONFIRM]`.
The registration procedure is **[VERIFY]**: see the ENISA page
<https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp>
(not read for this draft).

## 4. Deciding whether it is reportable

Ask these in order, at T0 and again whenever facts change. Over-report first; the
severity and the decision can be revised.

1. Is there credible evidence a malicious actor is **using** a flaw in Keyorix, in
   a customer system, in our systems, or in a published artifact? (customer report,
   researcher proof with exploitation, public exploitation write-up, our own detection)
   → **actively exploited vulnerability**.
2. Is there a compromise or event that **affects the security of the product** itself,
   not just of a customer's deployment? Examples from the IR plan: a malicious or
   tampered release or image, a compromised signing identity or release pipeline
   (IR plan 8.3), planted malicious code. → **severe incident**. [VERIFY] with counsel
   which of the IR plan's SEV1/SEV2 cases meet the regulation's definition.
3. Neither, but unsure → record the reasoning in the incident record and treat as
   reportable until counsel or the IC resolves it within 4 hours. [DECISION] Andrei to
   confirm that 4 h window.
4. A customer's own incident where Keyorix worked as designed is the customer's to
   report (IR plan, scope paragraph), not ours.

The IR plan's SEV scale and the CRA triggers are separate. A SEV1/SEV2 usually
coincides with a trigger, but a trigger can arise from a SEV3 (a report that turns out
to be exploited in the wild).

## 5. Internal timeline template

T0 is **the moment we became aware** that the vulnerability is actively exploited or
that a severe incident occurred. Not the moment of the first report in the mailbox if
that report did not indicate exploitation. Write the UTC timestamp and the basis in the
incident record (IR plan section 4). If the basis is arguable, use the earlier time.

Copy into the private incident record (`INC-YYYY-MM-DD-<slug>`), never into this
public repository:

```
CRA REPORTING TIMELINE   incident: INC-____   IC: ____   filer: ____

T0  aware (UTC): ____________   basis: ____________________
    Trigger:  [ ] actively exploited vulnerability   [ ] severe incident   [ ] undecided (decide by T0+4h)
    Affected products/versions: ____________________
    Deadlines (fill in at T0):
      Early warning due   T0+24h  = ______________ (UTC)
      Notification due    T0+72h  = ______________ (UTC)
      Final report due    vulnerability: 14 days after a corrective/mitigating
                          measure is available  = ______________ (set when known)
                          severe incident: 1 month after the 72h notification
                          = ______________ (UTC)       [VERIFY periods]

T0+1h   [ ] IR plan first-hour checklist started; evidence snapshots taken (section 8)
        [ ] SRP login confirmed working; filer present
T0+4h   [ ] reportable? decision recorded (yes / no / undecided -> treated as yes)
T0+12h  [ ] early warning drafted (section 6.1); counsel/second person asked
T0+20h  [ ] early warning SUBMITTED, reference no. ______   (hard stop: T0+24h)
T0+24h  [ ] confirmation / SRP reference stored in the record
T0+48h  [ ] notification drafted (section 6.2)
T0+68h  [ ] notification SUBMITTED, reference no. ______   (hard stop: T0+72h)
        [ ] customers/users informed (advisory draft ready; SECURITY.md process)
fix     [ ] corrective or mitigating measure available at (UTC) ______  -> final report
        due 14 days later (vulnerability case)
final   [ ] final report SUBMITTED, reference no. ______ , due ______
close   [ ] IR plan section 9 closing checklist; policy updates recorded
```

The submit targets are set 4 hours before the hard stop deliberately: one person
filing on a government platform needs slack for logins, outages and form problems.
If the SRP is unavailable, send the report through the fallback channel the platform
documents and record the outage; **[VERIFY]** what that fallback channel is.

## 6. Notification templates

Working templates. The legal minimum content per stage is **[VERIFY]** against
Article 14 and the SRP form; use the platform's fields where they differ. Mark unknowns
"unknown", not blank. A short report on time beats a complete one late; later stages
update earlier ones.

### 6.1 Early warning (T0 + 24 h)

```
Manufacturer: Keyorix SL (Valencia, Spain)        Contact: security@keyorix.com, <phone>
Product: Keyorix (server / CLI / container images)   Affected versions: ____ (or "under investigation")
Type: [ ] actively exploited vulnerability   [ ] severe incident
Became aware (UTC): ____
Summary (2-3 sentences, facts only): ____
Evidence of exploitation: ____ (source; "unknown" if not established)
Suspected unlawful or malicious cause?: [yes / no / unknown]  [VERIFY this field]
Member States where the product is available/affected: ____ [VERIFY whether the form asks]
Mitigation available to users right now: ____ (or "none yet")
```

### 6.2 Notification (T0 + 72 h)

```
Reference to early warning: ____
Update on the above, plus:
Nature of the vulnerability or incident and its general characteristics: ____
Affected products and versions (exact, with release tags and image digests): ____
Exploitation: how, since when, scale as known: ____
Root cause assessment so far: ____
Corrective or mitigating measures taken or planned; user-side mitigations: ____
Fix status: [ ] not started  [ ] in progress, ETA ____  [ ] released in ____
Users informed?: how and when (GHSA, release notes, direct email): ____
Sensitivity of the information / confidentiality request: ____ [VERIFY]
Assessed severity and impact on the security of the product: ____
```

### 6.3 Final report

```
Reference to notification: ____
Description of the vulnerability or incident, incl. severity and impact: ____
Type of threat or root cause: ____
Mitigation and corrective measures applied; fixed versions and advisory (GHSA/CVE): ____
Malicious actor information, if known: ____ (no speculation about attribution)
Remaining exposure: ____        Lessons / process changes: ____
Date a corrective or mitigating measure became available (UTC): ____
```

For a severe incident that is still ongoing at one month, send a progress report and
the final report when it is over; **[VERIFY]** the interim-report rule in Article 14.

## 7. How this ties into SECURITY.md and the IR plan

| Existing document | Link to the CRA path |
|---|---|
| `SECURITY.md` § Reporting a Vulnerability | Intake via GHSA private reporting or security@keyorix.com. The 48 h acknowledgement and 7 day assessment continue to apply; a report showing **live exploitation** is a CRA candidate at once, so the IC replies the same hour (as the IR plan already says) and starts the T0 template. |
| `SECURITY.md` § Remediation Timelines | The 90-day ceiling is unchanged. The CRA 24 h / 72 h / 14-day clocks are regulator notices, not fix deadlines, and run **in parallel** with the private-fork fix and the one-week advance notice. A CRA notification does not publish the vulnerability to the public: it goes to the CSIRT/ENISA. Whether to ask for confidential treatment is [VERIFY]. |
| `SECURITY.md` § Advisories | The GHSA published with the fix is also the "inform users" channel. If exploitation is ongoing and users need mitigation before a fix, the IC decides with counsel on an earlier advisory or a direct customer email (IR plan section 5). |
| `SECURITY.md` § Supported Versions / `SUPPORT.md` | The reporting duty is independent of the support table. A vulnerability exploited in an **unsupported** version still falls to [DECISION] 3, not silently out of scope. |
| IR plan sections 4, 6, 7 | First-hour checklist and evidence preservation apply unchanged. Section 7's CRA row should be updated to point here when this document is adopted (proposed text is in the session report; the IR plan is not edited in this PR). |
| IR plan section 8.3 (malicious release) | Almost certainly a CRA "severe incident". The 24 h clock runs from the time we confirm the artifact is malicious or reasonably suspect it is, whichever is earlier. Record that decision. |
| ADR-104 | Its 90-day / 7-day / same-day commitments are customer-facing. Its follow-up list asks the CRA chain, when written, to cross-reference it: this document does. |

## 8. Evidence to keep

Keep, in the private incident record with SHA-256 of each file (IR plan section 6 applies
in full), and retain after closure for the period counsel confirms
(`[retention: CONFIRM WITH COUNSEL]`):

1. The T0 decision: who became aware, when, how, and the basis (messages, logs).
2. The reportable / not-reportable decision and its reasoning, including "not
   reportable" decisions (these are the ones asked about later).
3. Every submission **as sent** (text or screenshots of the SRP form), the SRP
   confirmation or reference numbers, and the submission timestamps.
4. Evidence of exploitation and of the vulnerability: proof of concept, logs,
   researcher correspondence, affected versions and digests.
5. Fix evidence: the private advisory, commits, release tags, image digests, signatures
   and attestations (`SECURITY.md` § Verifying a Release), the date the corrective or
   mitigating measure became available.
6. User communications as sent: GHSA, release notes, emails, and recipient lists.
7. The timeline and scribe notes, counsel advice, and the post-incident review.
8. Failed attempts: SRP outages, login problems, with timestamps.

## 9. One-page checklist

```
CRA REPORT CHECKLIST (print this page)
[ ] 1  Write T0 (UTC) and its basis. Start the timeline. Open INC-record (private).
[ ] 2  Exploited vulnerability, or severe incident, or unsure? (section 4). Unsure = treat as yes.
[ ] 3  Compute and write: early warning T0+24h, notification T0+72h.
[ ] 4  Log in to the SRP now. Not working? Deputy / fallback channel [VERIFY].
[ ] 5  Evidence snapshots first (IR plan section 6), then contain.
[ ] 6  Draft early warning (6.1). Second person reads if reachable within 1h. File by T0+20h.
[ ] 7  Store SRP reference number + as-sent copy.
[ ] 8  Fix in the private advisory fork (SECURITY.md). Draft the GHSA. Tell users what to do.
[ ] 9  Draft and file notification (6.2) by T0+68h.
[ ] 10 When a corrective/mitigating measure is available: write the time. Final report due +14 days (vuln).
       Severe incident: final report due 1 month after the 72h notification.
[ ] 11 File the final report (6.3). Store the copy.
[ ] 12 Close with the IR plan section 9. Update this document where it was wrong.
Contacts: security@keyorix.com | SRP: ENISA single reporting platform | contact sheet: [location]
```

## 10. Open items before adoption

- Counsel and Andrei: [DECISION] 1-5 in section 2.
- Verify every [VERIFY] against the Official Journal text. Marker count and the list are
  in the session report. Notably: Article 14 paragraph numbers and content requirements;
  the Article 3 definitions; Article 13(8) wording; the Annex III item list; Spain's
  coordinator CSIRT; the SRP registration steps and fallback channel.
- Register on the SRP and create the deputy account; test login quarterly.
- Run a tabletop on the T0 timeline (extend `tabletop-1.md` or add `tabletop-2.md`).
- Reconcile `SECURITY.md` lines 79-82, `SUPPORT.md` § Current status and the IR plan
  section 7 CRA row after [DECISION] 3.
- Reconcile with ADR-104's amendment text (not edited here; see session report).
