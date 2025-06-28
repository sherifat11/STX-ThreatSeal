
;; STX-ThreatSeal


;; Error codes
(define-constant ACCESS_FORBIDDEN (err u100))
(define-constant DUPLICATE_ENTRY_ERROR (err u101))
(define-constant ENTRY_MISSING_ERROR (err u102))
(define-constant OPERATION_BLOCKED_ERROR (err u103))
(define-constant COLLATERAL_MISSING_ERROR (err u104))
(define-constant TIME_RESTRICTION_ERROR (err u105))
(define-constant LIMIT_BREACH_ERROR (err u106))
(define-constant TEMPORAL_ERROR (err u107))
(define-constant INVALID_WEB_IDENTIFIER (err u400))
(define-constant INVALID_SECURITY_ENDORSEMENT (err u401))
(define-constant INVALID_PROOF_DOCUMENTATION (err u402))
(define-constant INVALID_THREAT_MAGNITUDE (err u403))
(define-constant INVALID_PROTECTION_LEVEL (err u404))
(define-constant INVALID_CONTROLLER_ADDRESS (err u405))

;; System constants
(define-constant INACTIVITY_WINDOW u86400) ;; 24 hours in seconds
(define-constant BASE_COLLATERAL_REQUIREMENT u1000000) ;; in microSTX
(define-constant TRUSTWORTHINESS_BASELINE u50)
(define-constant EVIDENCE_STRING_LIMIT u500)


(define-data-var system_controller principal tx-sender)
(define-data-var entry_validation_cost uint u100)
(define-data-var alert_confirmation_minimum uint u5)
(define-data-var protection_intensity uint u1)
(define-data-var system_pause_state bool false)


;; Input validation functions
(define-private (validate-web-identifier (web_id (string-ascii 255)))
    (begin
        (asserts! (>= (len web_id) u3) (err "Web ID too short"))  ;; Minimum length check
        (asserts! (<= (len web_id) u255) (err "Web ID too long"))  ;; Maximum length check
        (asserts! (is-eq (index-of web_id ".") none) (err "Invalid character: ."))  ;; No direct dots allowed
        (asserts! (is-eq (index-of web_id "/") none) (err "Invalid character: /"))  ;; No direct slashes allowed
        (asserts! (is-eq (index-of web_id " ") none) (err "Invalid character: space"))  ;; No spaces allowed
        (ok true)))

(define-private (validate-security-endorsement (endorsement (string-ascii 50)))
    (begin
        (asserts! (>= (len endorsement) u5) (err "Endorsement too short"))  ;; Minimum length check
        (asserts! (<= (len endorsement) u50) (err "Endorsement too long"))  ;; Maximum length check
        (asserts! (is-eq (index-of endorsement "<") none) (err "Invalid character: <"))  ;; No HTML-like characters
        (asserts! (is-eq (index-of endorsement ">") none) (err "Invalid character: >"))
        (ok true)))

(define-private (validate-proof-documentation (proof (string-ascii 500)))
    (begin
        (asserts! (>= (len proof) u10) (err "Proof documentation too short"))
        (asserts! (<= (len proof) u500) (err "Proof documentation too long"))
        (asserts! (is-eq (index-of proof "<") none) (err "Invalid character: <"))
        (asserts! (is-eq (index-of proof ">") none) (err "Invalid character: >"))
        (ok true)))

(define-private (validate-threat-magnitude (magnitude uint))
    (begin
        (asserts! (>= magnitude u1) (err "Threat magnitude too low"))
        (asserts! (<= magnitude u100) (err "Threat magnitude too high"))
        (ok true)))

(define-private (validate-protection-level (level uint))
    (begin
        (asserts! (>= level u1) (err "Protection level too low"))
        (asserts! (<= level u10) (err "Protection level too high"))
        (ok true)))


;; Primary data structures
(define-map registered_sites
    {web_identifier: (string-ascii 255)}
    {
        site_proprietor: principal,
        authentication_level: (string-ascii 20),
        registration_epoch: uint,
        threat_metric: uint,
        incident_tally: uint,
        locked_assets: uint,
        safety_check_epoch: uint,
        security_endorsement: (string-ascii 50)
    })

(define-map sentinel_performance_log
    {sentinel_id: principal, target_site: (string-ascii 255)}
    {
        submission_count: uint,
        last_action_epoch: uint,
        credibility_score: uint,
        reserved_funds: uint,
        verified_submissions: uint
    })

(define-map site_inspection_records
    {web_identifier: (string-ascii 255)}
    {
        inspection_frequency: uint,
        recent_check_epoch: uint,
        inspector_id: principal,
        safety_rating: uint,
        compliance_status: (string-ascii 50)
    })

(define-map malicious_site_registry
    {web_identifier: (string-ascii 255)}
    {
        alerting_entity: principal,
        detection_epoch: uint,
        proof_documentation: (string-ascii 500),
        confirmation_state: (string-ascii 20),
        threat_magnitude: uint,
        victim_count: uint
    })



(define-map sentinel_registry
    {sentinel_id: principal}
    {
        reserved_amount: uint,
        assessment_count: uint,
        precision_metric: uint,
        recent_activity_epoch: uint,
        operational_mode: (string-ascii 20)
    })


(define-read-only (check_threat_status (web_identifier (string-ascii 255)))
    (is-some (map-get? malicious_site_registry {web_identifier: web_identifier})))

(define-read-only (fetch_sentinel_rating (sentinel_id principal))
    (match (map-get? sentinel_performance_log {sentinel_id: sentinel_id, target_site: ""})
        some_data (get credibility_score some_data)
        u0))

(define-read-only (fetch_site_status (web_identifier (string-ascii 255)))
    (match (map-get? registered_sites {web_identifier: web_identifier})
        some_entry (ok some_entry)
        (err ENTRY_MISSING_ERROR)))


;; Core operations
(define-public (register_secure_site 
    (web_identifier (string-ascii 255))
    (security_endorsement (string-ascii 50)))
    (let (
        (current_epoch (unwrap-panic (get-stacks-block-info? time (- stacks-block-height u1))))
        (collateral_requirement (* BASE_COLLATERAL_REQUIREMENT (var-get protection_intensity))))

        ;; Input validation
        (asserts! (is-ok (validate-web-identifier web_identifier)) INVALID_WEB_IDENTIFIER)
        (asserts! (is-ok (validate-security-endorsement security_endorsement)) INVALID_SECURITY_ENDORSEMENT)
        (asserts! (is-eq tx-sender (var-get system_controller)) ACCESS_FORBIDDEN)
        (asserts! (>= (stx-get-balance tx-sender) collateral_requirement) COLLATERAL_MISSING_ERROR)

        (match (map-get? registered_sites {web_identifier: web_identifier})
            some_entry DUPLICATE_ENTRY_ERROR
            (begin
                (try! (stx-transfer? collateral_requirement tx-sender (as-contract tx-sender)))
                (map-set registered_sites
                    {web_identifier: web_identifier}
                    {
                        site_proprietor: tx-sender,
                        authentication_level: "verified",
                        registration_epoch: current_epoch,
                        threat_metric: u0,
                        incident_tally: u0,
                        locked_assets: collateral_requirement,
                        safety_check_epoch: current_epoch,
                        security_endorsement: security_endorsement
                    })
                (ok true)))))


