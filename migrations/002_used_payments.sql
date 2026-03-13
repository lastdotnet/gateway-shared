CREATE TABLE IF NOT EXISTS used_payments (
    payment_key VARCHAR(255) PRIMARY KEY,
    scheme VARCHAR(20) NOT NULL,
    payer VARCHAR(42) NOT NULL,
    token VARCHAR(42),
    amount_raw VARCHAR(78),
    tx_hash VARCHAR(66),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_used_payments_payer ON used_payments(payer);
CREATE INDEX IF NOT EXISTS idx_used_payments_created_at ON used_payments(created_at);
