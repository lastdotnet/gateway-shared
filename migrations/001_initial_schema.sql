CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES accounts(id),
    key_hash BYTEA NOT NULL UNIQUE,
    key_prefix VARCHAR(8) NOT NULL,
    name VARCHAR(255),
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_api_keys_account_active ON api_keys(account_id, is_active);

CREATE TABLE IF NOT EXISTS credit_balances (
    account_id UUID PRIMARY KEY REFERENCES accounts(id),
    balance_usd NUMERIC(20, 8) NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (balance_usd >= 0)
);

CREATE TABLE IF NOT EXISTS ledger_entries (
    id BIGSERIAL PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id),
    entry_type VARCHAR(20) NOT NULL,
    amount_usd NUMERIC(20, 8) NOT NULL,
    balance_after NUMERIC(20, 8) NOT NULL,
    reference_type VARCHAR(50) NOT NULL,
    reference_id VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ledger_account_created_at ON ledger_entries(account_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_reference ON ledger_entries(reference_type, reference_id);

CREATE TABLE IF NOT EXISTS deposits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES accounts(id),
    chain VARCHAR(20) NOT NULL,
    tx_hash VARCHAR(66) NOT NULL UNIQUE,
    token_address VARCHAR(42),
    amount_raw NUMERIC(78, 0) NOT NULL,
    amount_usd NUMERIC(20, 8) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'confirmed',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS usage_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES accounts(id),
    request_id VARCHAR(255) NOT NULL UNIQUE,
    model VARCHAR(100) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    total_cost_usd NUMERIC(20, 8) NOT NULL,
    payment_mode VARCHAR(20) NOT NULL,
    latency_ms INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_usage_account_created_at ON usage_records(account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_model_provider ON usage_records(model, provider);

CREATE TABLE IF NOT EXISTS model_pricing (
    model_id VARCHAR(100) PRIMARY KEY,
    provider VARCHAR(50) NOT NULL,
    input_price_per_million NUMERIC(10, 4) NOT NULL,
    output_price_per_million NUMERIC(10, 4) NOT NULL,
    context_window INTEGER NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS deposit_addresses (
    account_id UUID PRIMARY KEY REFERENCES accounts(id),
    evm_address VARCHAR(42) NOT NULL UNIQUE,
    hypercore_address VARCHAR(42) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
