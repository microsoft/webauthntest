-- D1 schema for Passkey Playground (edge-native)

CREATE TABLE IF NOT EXISTS credentials (
  uid TEXT NOT NULL,
  id TEXT NOT NULL,
  rpId TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  transports TEXT,
  createdAt INTEGER NOT NULL,
  data TEXT NOT NULL,
  PRIMARY KEY (uid, id)
);

CREATE INDEX IF NOT EXISTS idx_credentials_uid_rpId ON credentials(uid, rpId);
CREATE INDEX IF NOT EXISTS idx_credentials_uid ON credentials(uid);
