

# STX-ThreatSeal - Threat Sentinel Protocol (TSP)

## Overview

The **Threat Sentinel Protocol (TSP)** is a decentralized web security registry and threat mitigation system implemented in Clarity for the Stacks blockchain. It facilitates secure site registration, threat alert submission by verified sentinels, and dynamic threat intelligence aggregation through transparent smart contracts.

This contract ensures trust and resilience by combining:

* **Web resource registration** with locked collateral,
* **Sentinel-based threat reporting** with credibility scoring,
* **On-chain inspection and validation mechanisms**, and
* **Configurable governance and system parameters**.

---

## 🧱 Core Components

### 🔐 `register_secure_site`

Registers a secure website with a web identifier and a security endorsement, after locking collateral.

* Requires controller access.
* Performs validation on input format.
* Fails if site already exists or collateral is insufficient.

### 🛡️ `submit_threat_alert`

Allows sentinels to report a malicious site by submitting documented proof and threat magnitude.

* Requires valid credentials and cooldown period.
* Credibility score must meet a minimum threshold.
* Updates performance logs and registry status.

### ✅ `validate_threat_report`

Used by sentinels to confirm or reject previous threat alerts.

* Updates site threat metrics (+10 for valid, -5 for invalid).
* Tracks sentinel assessment history.

### 🛠️ `modify_protection_level`

Changes the base multiplier for collateral requirements. Admin-only.

### ⏸️ `toggle_system_state`

Pauses or resumes all sensitive system operations. Admin-only.

### 🔁 `reassign_system_control`

Transfers contract control to another principal. Admin-only, with restrictions.

### 🆕 `initialize_system`

Performs first-time initialization with controller setup and system defaults.

### 🎯 `enlist_sentinel`

Registers a new sentinel with collateral and logs initial metadata.

---

## 🗂️ Data Structures

### `registered_sites`

Tracks registered sites' metadata including:

* Proprietor
* Registration time
* Threat metrics
* Locked funds
* Security endorsement

### `malicious_site_registry`

Logs all threat alerts, including:

* Reporter
* Documentation
* Threat level
* Confirmation state

### `sentinel_registry`

Holds information about each sentinel:

* Reserved collateral
* Precision metric
* Activity status

### `sentinel_performance_log`

Tracks per-site sentinel submissions and ratings.

### `site_inspection_records`

Tracks inspections and site compliance status.

---

## 🔍 Read-only Functions

| Function                              | Description                                  |
| ------------------------------------- | -------------------------------------------- |
| `check_threat_status(web_identifier)` | Returns whether a site is currently flagged. |
| `fetch_sentinel_rating(sentinel_id)`  | Returns a sentinel's credibility score.      |
| `fetch_site_status(web_identifier)`   | Retrieves metadata for a registered site.    |

---

## 🧪 Input Validators

* `validate-web-identifier`: Disallows symbols like `.`, `/`, spaces.
* `validate-security-endorsement`: No HTML characters.
* `validate-proof-documentation`: Length and format enforced.
* `validate-threat-magnitude`: 1–100.
* `validate-protection-level`: 1–10.

---

## 🔒 Error Handling

| Error Constant             | Code    | Description                           |
| -------------------------- | ------- | ------------------------------------- |
| `ACCESS_FORBIDDEN`         | 100     | Caller lacks required permissions     |
| `DUPLICATE_ENTRY_ERROR`    | 101     | Site is already registered            |
| `ENTRY_MISSING_ERROR`      | 102     | Record not found                      |
| `OPERATION_BLOCKED_ERROR`  | 103     | System is paused                      |
| `COLLATERAL_MISSING_ERROR` | 104     | STX collateral insufficient           |
| `TIME_RESTRICTION_ERROR`   | 105     | Sentinel not eligible due to cooldown |
| `LIMIT_BREACH_ERROR`       | 106     | Constraints exceeded                  |
| `TEMPORAL_ERROR`           | 107     | Invalid timing                        |
| `INVALID_*`                | 400–405 | Input format violations               |

---

## ⚙️ System Constants

* `INACTIVITY_WINDOW`: 24h cooldown (86400 seconds)
* `BASE_COLLATERAL_REQUIREMENT`: 1,000,000 microSTX
* `TRUSTWORTHINESS_BASELINE`: Sentinel credibility threshold (50)
* `EVIDENCE_STRING_LIMIT`: Max size of proof (500 chars)

---

## 🔧 Admin Controls

| Function                  | Purpose                                |
| ------------------------- | -------------------------------------- |
| `modify_protection_level` | Change system's collateral multiplier  |
| `toggle_system_state`     | Pause or resume core operations        |
| `reassign_system_control` | Assign contract control to a new admin |
| `initialize_system`       | Set up admin and system parameters     |

---

## ✅ Deployment Notes

1. Deploy using a trusted admin address.
2. Immediately call `initialize_system` to establish the controller.
3. Configure `protection_intensity` as needed.
4. Monitor sentinel credibility via `sentinel_performance_log`.

---
