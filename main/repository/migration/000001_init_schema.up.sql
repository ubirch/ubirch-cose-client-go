CREATE TABLE IF NOT EXISTS cose_identity_hsm
(
    uid        VARCHAR(255) NOT NULL PRIMARY KEY,
    public_key VARCHAR(255) NOT NULL,
    auth       VARCHAR(255) NOT NULL
);