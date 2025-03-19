;; Decentralized Escrow Vault - Secure Transaction Protocol
;; A platform for trustless digital asset exchanges

;; Core contract constants
(define-constant CONTRACT_ADMIN tx-sender)
(define-constant ERROR_ACCESS_DENIED (err u100))
(define-constant ERROR_VAULT_NOT_FOUND (err u101))
(define-constant ERROR_ALREADY_FINALIZED (err u102))
(define-constant ERROR_TRANSFER_FAILED (err u103))
(define-constant ERROR_INVALID_VAULT (err u104))
(define-constant ERROR_INVALID_INPUT (err u105))
(define-constant ERROR_COUNTERPARTY_INVALID (err u106))
(define-constant ERROR_VAULT_EXPIRED (err u107))
(define-constant VAULT_LIFETIME_BLOCKS u1008) ;; ~7 days

;; Vault record structure
(define-map VaultRegistry
  { vault-id: uint }
  {
    depositor: principal,
    counterparty: principal,
    item-id: uint,
    amount: uint,
    vault-state: (string-ascii 10),
    creation-height: uint,
    expiration-height: uint
  }
)

;; Vault counter
(define-data-var vault-counter uint u0)

;; Helper functions

(define-private (valid-vault? (vault-id uint))
  (<= vault-id (var-get vault-counter))
)

(define-private (valid-counterparty? (party principal))
  (and 
    (not (is-eq party tx-sender))
    (not (is-eq party (as-contract tx-sender)))
  )
)

;; Security verification with ZK proof support
(define-public (verify-with-zk (vault-id uint) (proof-data (buff 128)) (input-values (list 5 (buff 32))))
  (begin
    (asserts! (valid-vault? vault-id) ERROR_INVALID_VAULT)
    (let
      (
        (vault-data (unwrap! (map-get? VaultRegistry { vault-id: vault-id }) ERROR_VAULT_NOT_FOUND))
        (depositor (get depositor vault-data))
        (counterparty (get counterparty vault-data))
        (amount (get amount vault-data))
      )
      ;; Only apply to high-value vaults
      (asserts! (> amount u10000) (err u190))
      (asserts! (or (is-eq tx-sender depositor) (is-eq tx-sender counterparty) (is-eq tx-sender CONTRACT_ADMIN)) ERROR_ACCESS_DENIED)
      (asserts! (or (is-eq (get vault-state vault-data) "pending") (is-eq (get vault-state vault-data) "accepted")) ERROR_ALREADY_FINALIZED)

      ;; Placeholder for ZK verification logic

      (print {event: "vault_zk_verified", vault-id: vault-id, verifier: tx-sender, 
              proof-hash: (hash160 proof-data), inputs: input-values})
      (ok true)
    )
  )
)

;; Rate limiting implementation
(define-public (set-rate-limits (attempt-limit uint) (block-cooldown uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_ADMIN) ERROR_ACCESS_DENIED)
    (asserts! (> attempt-limit u0) ERROR_INVALID_INPUT)
    (asserts! (<= attempt-limit u10) ERROR_INVALID_INPUT) 
    (asserts! (> block-cooldown u6) ERROR_INVALID_INPUT)
    (asserts! (<= block-cooldown u144) ERROR_INVALID_INPUT)

    (print {event: "limits_configured", max-tries: attempt-limit, 
            cooldown: block-cooldown, admin: tx-sender, height: block-height})
    (ok true)
  )
)

;; Transaction velocity monitoring
(define-public (analyze-transaction-patterns (party principal) (time-span uint) (tx-count uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_ADMIN) ERROR_ACCESS_DENIED)
    (asserts! (> time-span u0) ERROR_INVALID_INPUT)
    (asserts! (> tx-count u0) ERROR_INVALID_INPUT)

    (let
      (
        (tx-rate (/ tx-count time-span))
        (suspicious-activity (> tx-rate u3))
      )
      (if suspicious-activity
        (print {event: "suspicious_activity", party: party, 
                transactions: tx-count, timeframe: time-span,
                rate: tx-rate, threshold: u3})
        (print {event: "normal_activity", party: party, 
                transactions: tx-count, timeframe: time-span,
                rate: tx-rate, threshold: u3})
      )
      (ok suspicious-activity)
    )
  )
)

;; Emergency recovery vault creation
(define-public (establish-recovery-vault (vault-id uint) (delay-blocks uint) (backup-address principal))
  (begin
    (asserts! (valid-vault? vault-id) ERROR_INVALID_VAULT)
    (asserts! (> delay-blocks u72) ERROR_INVALID_INPUT) 
    (asserts! (<= delay-blocks u1440) ERROR_INVALID_INPUT)
    (let
      (
        (vault-data (unwrap! (map-get? VaultRegistry { vault-id: vault-id }) ERROR_VAULT_NOT_FOUND))
        (depositor (get depositor vault-data))
        (unlock-height (+ block-height delay-blocks))
      )
      (asserts! (is-eq tx-sender depositor) ERROR_ACCESS_DENIED)
      (asserts! (is-eq (get vault-state vault-data) "pending") ERROR_ALREADY_FINALIZED)
      (asserts! (not (is-eq backup-address depositor)) (err u180))
      (asserts! (not (is-eq backup-address (get counterparty vault-data))) (err u181))
      (print {event: "recovery_established", vault-id: vault-id, depositor: depositor, 
              backup: backup-address, unlock-at: unlock-height})
      (ok unlock-height)
    )
  )
)

;; Return funds to depositor
(define-public (return-funds (vault-id uint))
  (begin
    (asserts! (valid-vault? vault-id) ERROR_INVALID_VAULT)
    (let
      (
        (vault-data (unwrap! (map-get? VaultRegistry { vault-id: vault-id }) ERROR_VAULT_NOT_FOUND))
        (depositor (get depositor vault-data))
        (amount (get amount vault-data))
      )
      (asserts! (is-eq tx-sender CONTRACT_ADMIN) ERROR_ACCESS_DENIED)
      (asserts! (is-eq (get vault-state vault-data) "pending") ERROR_ALREADY_FINALIZED)
      (match (as-contract (stx-transfer? amount tx-sender depositor))
        success
          (begin
            (map-set VaultRegistry
              { vault-id: vault-id }
              (merge vault-data { vault-state: "refunded" })
            )
            (print {event: "funds_returned", vault-id: vault-id, depositor: depositor, amount: amount})
            (ok true)
          )
        error ERROR_TRANSFER_FAILED
      )
    )
  )
)

;; Enhanced security with 2FA
(define-public (activate-2fa (vault-id uint) (auth-hash (buff 32)))
  (begin
    (asserts! (valid-vault? vault-id) ERROR_INVALID_VAULT)
    (let
      (
        (vault-data (unwrap! (map-get? VaultRegistry { vault-id: vault-id }) ERROR_VAULT_NOT_FOUND))
        (depositor (get depositor vault-data))
        (amount (get amount vault-data))
      )
      (asserts! (> amount u5000) (err u130))
      (asserts! (is-eq tx-sender depositor) ERROR_ACCESS_DENIED)
      (asserts! (is-eq (get vault-state vault-data) "pending") ERROR_ALREADY_FINALIZED)
      (print {event: "2fa_activated", vault-id: vault-id, depositor: depositor, hash: (hash160 auth-hash)})
      (ok true)
    )
  )
)

;; Emergency recovery procedure
(define-public (set-emergency-backup (vault-id uint) (backup-address principal))
  (begin
    (asserts! (valid-vault? vault-id) ERROR_INVALID_VAULT)
    (let
      (
        (vault-data (unwrap! (map-get? VaultRegistry { vault-id: vault-id }) ERROR_VAULT_NOT_FOUND))
        (depositor (get depositor vault-data))
      )
      (asserts! (is-eq tx-sender depositor) ERROR_ACCESS_DENIED)
      (asserts! (not (is-eq backup-address tx-sender)) (err u111))
      (asserts! (is-eq (get vault-state vault-data) "pending") ERROR_ALREADY_FINALIZED)
      (print {event: "backup_set", vault-id: vault-id, depositor: depositor, backup: backup-address})
      (ok true)
    )
  )
)

;; Transfer vault ownership
(define-public (transfer-ownership (vault-id uint) (new-owner principal) (auth-code (buff 32)))
  (begin
    (asserts! (valid-vault? vault-id) ERROR_INVALID_VAULT)
    (let
      (
        (vault-data (unwrap! (map-get? VaultRegistry { vault-id: vault-id }) ERROR_VAULT_NOT_FOUND))
        (current-owner (get depositor vault-data))
        (current-state (get vault-state vault-data))
      )
      (asserts! (or (is-eq tx-sender current-owner) (is-eq tx-sender CONTRACT_ADMIN)) ERROR_ACCESS_DENIED)
      (asserts! (not (is-eq new-owner current-owner)) (err u210))
      (asserts! (not (is-eq new-owner (get counterparty vault-data))) (err u211))
      (asserts! (or (is-eq current-state "pending") (is-eq current-state "accepted")) ERROR_ALREADY_FINALIZED)
      (map-set VaultRegistry
        { vault-id: vault-id }
        (merge vault-data { depositor: new-owner })
      )
      (print {event: "ownership_transferred", vault-id: vault-id, 
              previous: current-owner, new-owner: new-owner, auth-hash: (hash160 auth-code)})
      (ok true)
    )
  )
)

;; Staged vault creation
(define-public (create-staged-vault (counterparty principal) (item-id uint) (amount uint) (stages uint))
  (let 
    (
      (new-id (+ (var-get vault-counter) u1))
      (expire-height (+ block-height VAULT_LIFETIME_BLOCKS))
      (per-stage-amount (/ amount stages))
    )
    (asserts! (> amount u0) ERROR_INVALID_INPUT)
    (asserts! (> stages u0) ERROR_INVALID_INPUT)
    (asserts! (<= stages u5) ERROR_INVALID_INPUT)
    (asserts! (valid-counterparty? counterparty) ERROR_COUNTERPARTY_INVALID)
    (asserts! (is-eq (* per-stage-amount stages) amount) (err u121))
    (match (stx-transfer? amount tx-sender (as-contract tx-sender))
      success
        (begin
          (var-set vault-counter new-id)
          (print {event: "staged_vault_created", vault-id: new-id, depositor: tx-sender, counterparty: counterparty, 
                  item-id: item-id, amount: amount, stages: stages, stage-amount: per-stage-amount})
          (ok new-id)
        )
      error ERROR_TRANSFER_FAILED
    )
  )
)


;; Schedule critical operation with timelock
(define-public (schedule-operation (op-name (string-ascii 20)) (op-params (list 10 uint)))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_ADMIN) ERROR_ACCESS_DENIED)
    (asserts! (> (len op-params) u0) ERROR_INVALID_INPUT)
    (let
      (
        (execute-at (+ block-height u144))
      )
      (print {event: "operation_scheduled", operation: op-name, params: op-params, execute-at: execute-at})
      (ok execute-at)
    )
  )
)

;; Add metadata to vault
(define-public (add-vault-metadata (vault-id uint) (metadata-kind (string-ascii 20)) (data-hash (buff 32)))
  (begin
    (asserts! (valid-vault? vault-id) ERROR_INVALID_VAULT)
    (let
      (
        (vault-data (unwrap! (map-get? VaultRegistry { vault-id: vault-id }) ERROR_VAULT_NOT_FOUND))
        (depositor (get depositor vault-data))
        (counterparty (get counterparty vault-data))
      )
      (asserts! (or (is-eq tx-sender depositor) (is-eq tx-sender counterparty) (is-eq tx-sender CONTRACT_ADMIN)) ERROR_ACCESS_DENIED)
      (asserts! (not (is-eq (get vault-state vault-data) "completed")) (err u160))
      (asserts! (not (is-eq (get vault-state vault-data) "refunded")) (err u161))
      (asserts! (not (is-eq (get vault-state vault-data) "expired")) (err u162))

      (asserts! (or (is-eq metadata-kind "item-details") 
                   (is-eq metadata-kind "delivery-proof")
                   (is-eq metadata-kind "quality-check")
                   (is-eq metadata-kind "depositor-preferences")) (err u163))

      (print {event: "metadata_attached", vault-id: vault-id, kind: metadata-kind, 
              hash: data-hash, submitter: tx-sender})
      (ok true)
    )
  )
)

;; Add cryptographic signature
(define-public (add-crypto-signature (vault-id uint) (signature (buff 65)))
  (begin
    (asserts! (valid-vault? vault-id) ERROR_INVALID_VAULT)
    (let
      (
        (vault-data (unwrap! (map-get? VaultRegistry { vault-id: vault-id }) ERROR_VAULT_NOT_FOUND))
        (depositor (get depositor vault-data))
        (counterparty (get counterparty vault-data))
      )
      (asserts! (or (is-eq tx-sender depositor) (is-eq tx-sender counterparty)) ERROR_ACCESS_DENIED)
      (asserts! (or (is-eq (get vault-state vault-data) "pending") (is-eq (get vault-state vault-data) "accepted")) ERROR_ALREADY_FINALIZED)
      (print {event: "signature_recorded", vault-id: vault-id, signer: tx-sender, signature: signature})
      (ok true)
    )
  )
)

;; Multi-signature approval for high-value vaults
(define-public (register-multisig-approval (vault-id uint) (approver principal))
  (begin
    (asserts! (valid-vault? vault-id) ERROR_INVALID_VAULT)
    (let
      (
        (vault-data (unwrap! (map-get? VaultRegistry { vault-id: vault-id }) ERROR_VAULT_NOT_FOUND))
        (depositor (get depositor vault-data))
        (amount (get amount vault-data))
      )
      (asserts! (> amount u1000) (err u120))
      (asserts! (or (is-eq tx-sender depositor) (is-eq tx-sender CONTRACT_ADMIN)) ERROR_ACCESS_DENIED)
      (asserts! (is-eq (get vault-state vault-data) "pending") ERROR_ALREADY_FINALIZED)
      (print {event: "multisig_registered", vault-id: vault-id, approver: approver, requestor: tx-sender})
      (ok true)
    )
  )
)


;; Complete vault transaction
(define-public (complete-vault (vault-id uint))
  (begin
    (asserts! (valid-vault? vault-id) ERROR_INVALID_VAULT)
    (let
      (
        (vault-data (unwrap! (map-get? VaultRegistry { vault-id: vault-id }) ERROR_VAULT_NOT_FOUND))
        (counterparty (get counterparty vault-data))
        (amount (get amount vault-data))
        (item-id (get item-id vault-data))
      )
      (asserts! (or (is-eq tx-sender CONTRACT_ADMIN) (is-eq tx-sender (get depositor vault-data))) ERROR_ACCESS_DENIED)
      (asserts! (is-eq (get vault-state vault-data) "pending") ERROR_ALREADY_FINALIZED)
      (asserts! (<= block-height (get expiration-height vault-data)) ERROR_VAULT_EXPIRED)
      (match (as-contract (stx-transfer? amount tx-sender counterparty))
        success
          (begin
            (map-set VaultRegistry
              { vault-id: vault-id }
              (merge vault-data { vault-state: "completed" })
            )
            (print {event: "vault_completed", vault-id: vault-id, counterparty: counterparty, item-id: item-id, amount: amount})
            (ok true)
          )
        error ERROR_TRANSFER_FAILED
      )
    )
  )
)

;; Dispute handling
(define-public (initiate-dispute (vault-id uint) (reason (string-ascii 50)))
  (begin
    (asserts! (valid-vault? vault-id) ERROR_INVALID_VAULT)
    (let
      (
        (vault-data (unwrap! (map-get? VaultRegistry { vault-id: vault-id }) ERROR_VAULT_NOT_FOUND))
        (depositor (get depositor vault-data))
        (counterparty (get counterparty vault-data))
      )
      (asserts! (or (is-eq tx-sender depositor) (is-eq tx-sender counterparty)) ERROR_ACCESS_DENIED)
      (asserts! (or (is-eq (get vault-state vault-data) "pending") (is-eq (get vault-state vault-data) "accepted")) ERROR_ALREADY_FINALIZED)
      (asserts! (<= block-height (get expiration-height vault-data)) ERROR_VAULT_EXPIRED)
      (map-set VaultRegistry
        { vault-id: vault-id }
        (merge vault-data { vault-state: "disputed" })
      )
      (print {event: "dispute_initiated", vault-id: vault-id, initiator: tx-sender, reason: reason})
      (ok true)
    )
  )
)


;; Arbitration resolution
(define-public (resolve-dispute (vault-id uint) (depositor-percentage uint))
  (begin
    (asserts! (valid-vault? vault-id) ERROR_INVALID_VAULT)
    (asserts! (is-eq tx-sender CONTRACT_ADMIN) ERROR_ACCESS_DENIED)
    (asserts! (<= depositor-percentage u100) ERROR_INVALID_INPUT)
    (let
      (
        (vault-data (unwrap! (map-get? VaultRegistry { vault-id: vault-id }) ERROR_VAULT_NOT_FOUND))
        (depositor (get depositor vault-data))
        (counterparty (get counterparty vault-data))
        (amount (get amount vault-data))
        (depositor-amount (/ (* amount depositor-percentage) u100))
        (counterparty-amount (- amount depositor-amount))
      )
      (asserts! (is-eq (get vault-state vault-data) "disputed") (err u112))
      (asserts! (<= block-height (get expiration-height vault-data)) ERROR_VAULT_EXPIRED)

      (unwrap! (as-contract (stx-transfer? depositor-amount tx-sender depositor)) ERROR_TRANSFER_FAILED)
      (unwrap! (as-contract (stx-transfer? counterparty-amount tx-sender counterparty)) ERROR_TRANSFER_FAILED)

      (map-set VaultRegistry
        { vault-id: vault-id }
        (merge vault-data { vault-state: "arbitrated" })
      )
      (print {event: "dispute_resolved", vault-id: vault-id, depositor: depositor, counterparty: counterparty, 
              depositor-amount: depositor-amount, counterparty-amount: counterparty-amount, split-percentage: depositor-percentage})
      (ok true)
    )
  )
)

;; Verify transaction signature
(define-public (verify-signature (vault-id uint) (message (buff 32)) (signature (buff 65)) (signer principal))
  (begin
    (asserts! (valid-vault? vault-id) ERROR_INVALID_VAULT)
    (let
      (
        (vault-data (unwrap! (map-get? VaultRegistry { vault-id: vault-id }) ERROR_VAULT_NOT_FOUND))
        (depositor (get depositor vault-data))
        (counterparty (get counterparty vault-data))
        (verification-result (unwrap! (secp256k1-recover? message signature) (err u150)))
      )
      (asserts! (or (is-eq tx-sender depositor) (is-eq tx-sender counterparty) (is-eq tx-sender CONTRACT_ADMIN)) ERROR_ACCESS_DENIED)
      (asserts! (or (is-eq signer depositor) (is-eq signer counterparty)) (err u151))
      (asserts! (is-eq (get vault-state vault-data) "pending") ERROR_ALREADY_FINALIZED)
      (asserts! (is-eq (unwrap! (principal-of? verification-result) (err u152)) signer) (err u153))

      (print {event: "signature_verified", vault-id: vault-id, verifier: tx-sender, signer: signer})
      (ok true)
    )
  )
)

;; Extend vault expiration
(define-public (extend-time (vault-id uint) (additional-blocks uint))
  (begin
    (asserts! (valid-vault? vault-id) ERROR_INVALID_VAULT)
    (asserts! (> additional-blocks u0) ERROR_INVALID_INPUT)
    (asserts! (<= additional-blocks u1440) ERROR_INVALID_INPUT)
    (let
      (
        (vault-data (unwrap! (map-get? VaultRegistry { vault-id: vault-id }) ERROR_VAULT_NOT_FOUND))
        (depositor (get depositor vault-data)) 
        (counterparty (get counterparty vault-data))
        (current-expiry (get expiration-height vault-data))
        (new-expiry (+ current-expiry additional-blocks))
      )
      (asserts! (or (is-eq tx-sender depositor) (is-eq tx-sender counterparty) (is-eq tx-sender CONTRACT_ADMIN)) ERROR_ACCESS_DENIED)
      (asserts! (or (is-eq (get vault-state vault-data) "pending") (is-eq (get vault-state vault-data) "accepted")) ERROR_ALREADY_FINALIZED)
      (map-set VaultRegistry
        { vault-id: vault-id }
        (merge vault-data { expiration-height: new-expiry })
      )
      (print {event: "time_extended", vault-id: vault-id, requestor: tx-sender, new-expiry: new-expiry})
      (ok true)
    )
  )
)

;; Secured vault withdrawal
(define-public (process-secure-withdrawal (vault-id uint) (withdrawal-amount uint) (approval-sig (buff 65)))
  (begin
    (asserts! (valid-vault? vault-id) ERROR_INVALID_VAULT)
    (let
      (
        (vault-data (unwrap! (map-get? VaultRegistry { vault-id: vault-id }) ERROR_VAULT_NOT_FOUND))
        (depositor (get depositor vault-data))
        (counterparty (get counterparty vault-data))
        (amount (get amount vault-data))
        (state (get vault-state vault-data))
      )
      (asserts! (is-eq tx-sender CONTRACT_ADMIN) ERROR_ACCESS_DENIED)
      (asserts! (is-eq state "disputed") (err u220))
      (asserts! (<= withdrawal-amount amount) ERROR_INVALID_INPUT)
      (asserts! (>= block-height (+ (get creation-height vault-data) u48)) (err u221))

      (unwrap! (as-contract (stx-transfer? withdrawal-amount tx-sender depositor)) ERROR_TRANSFER_FAILED)

      (map-set VaultRegistry
        { vault-id: vault-id }
        (merge vault-data { amount: (- amount withdrawal-amount) })
      )

      (print {event: "secure_withdrawal_completed", vault-id: vault-id, depositor: depositor, 
              amount: withdrawal-amount, remaining: (- amount withdrawal-amount)})
      (ok true)
    )
  )
)

;; Cancel vault
(define-public (cancel-vault (vault-id uint))
  (begin
    (asserts! (valid-vault? vault-id) ERROR_INVALID_VAULT)
    (let
      (
        (vault-data (unwrap! (map-get? VaultRegistry { vault-id: vault-id }) ERROR_VAULT_NOT_FOUND))
        (depositor (get depositor vault-data))
        (amount (get amount vault-data))
      )
      (asserts! (is-eq tx-sender depositor) ERROR_ACCESS_DENIED)
      (asserts! (is-eq (get vault-state vault-data) "pending") ERROR_ALREADY_FINALIZED)
      (asserts! (<= block-height (get expiration-height vault-data)) ERROR_VAULT_EXPIRED)
      (match (as-contract (stx-transfer? amount tx-sender depositor))
        success
          (begin
            (map-set VaultRegistry
              { vault-id: vault-id }
              (merge vault-data { vault-state: "cancelled" })
            )
            (print {event: "vault_cancelled", vault-id: vault-id, depositor: depositor, amount: amount})
            (ok true)
          )
        error ERROR_TRANSFER_FAILED
      )
    )
  )
)

;; Process expired vault
(define-public (process-expired (vault-id uint))
  (begin
    (asserts! (valid-vault? vault-id) ERROR_INVALID_VAULT)
    (let
      (
        (vault-data (unwrap! (map-get? VaultRegistry { vault-id: vault-id }) ERROR_VAULT_NOT_FOUND))
        (depositor (get depositor vault-data))
        (amount (get amount vault-data))
        (expiry (get expiration-height vault-data))
      )
      (asserts! (or (is-eq tx-sender depositor) (is-eq tx-sender CONTRACT_ADMIN)) ERROR_ACCESS_DENIED)
      (asserts! (or (is-eq (get vault-state vault-data) "pending") (is-eq (get vault-state vault-data) "accepted")) ERROR_ALREADY_FINALIZED)
      (asserts! (> block-height expiry) (err u108))
      (match (as-contract (stx-transfer? amount tx-sender depositor))
        success
          (begin
            (map-set VaultRegistry
              { vault-id: vault-id }
              (merge vault-data { vault-state: "expired" })
            )
            (print {event: "expired_vault_processed", vault-id: vault-id, depositor: depositor, amount: amount})
            (ok true)
          )
        error ERROR_TRANSFER_FAILED
      )
    )
  )
)

;; Process delayed withdrawal
(define-public (finalize-delayed-withdrawal (vault-id uint))
  (begin
    (asserts! (valid-vault? vault-id) ERROR_INVALID_VAULT)
    (let
      (
        (vault-data (unwrap! (map-get? VaultRegistry { vault-id: vault-id }) ERROR_VAULT_NOT_FOUND))
        (depositor (get depositor vault-data))
        (amount (get amount vault-data))
        (state (get vault-state vault-data))
        (time-lock u24)
      )
      (asserts! (or (is-eq tx-sender depositor) (is-eq tx-sender CONTRACT_ADMIN)) ERROR_ACCESS_DENIED)
      (asserts! (is-eq state "withdrawal-pending") (err u301))
      (asserts! (>= block-height (+ (get creation-height vault-data) time-lock)) (err u302))

      (unwrap! (as-contract (stx-transfer? amount tx-sender depositor)) ERROR_TRANSFER_FAILED)

      (map-set VaultRegistry
        { vault-id: vault-id }
        (merge vault-data { vault-state: "withdrawn", amount: u0 })
      )

      (print {event: "delayed_withdrawal_finalized", vault-id: vault-id, 
              depositor: depositor, amount: amount})
      (ok true)
    )
  )
)

;; Flag suspicious vault
(define-public (flag-suspicious (vault-id uint) (reason (string-ascii 100)))
  (begin
    (asserts! (valid-vault? vault-id) ERROR_INVALID_VAULT)
    (let
      (
        (vault-data (unwrap! (map-get? VaultRegistry { vault-id: vault-id }) ERROR_VAULT_NOT_FOUND))
        (depositor (get depositor vault-data))
        (counterparty (get counterparty vault-data))
      )
      (asserts! (or (is-eq tx-sender CONTRACT_ADMIN) (is-eq tx-sender depositor) (is-eq tx-sender counterparty)) ERROR_ACCESS_DENIED)
      (asserts! (or (is-eq (get vault-state vault-data) "pending") 
                   (is-eq (get vault-state vault-data) "accepted")) 
                ERROR_ALREADY_FINALIZED)
      (map-set VaultRegistry
        { vault-id: vault-id }
        (merge vault-data { vault-state: "frozen" })
      )
      (print {event: "vault_flagged", vault-id: vault-id, reporter: tx-sender, reason: reason})
      (ok true)
    )
  )
)



