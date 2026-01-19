export async function initSchema(db) {
  // Optional: run schema.sql manually via wrangler. Keep runtime init minimal.
  // This exists mainly for tests/local tooling.
  return db;
}

export async function upsertCredential(db, credential) {
  const uid = credential.uid;
  const id = credential.id;
  const rpId = credential?.metadata?.rpId;
  const enabled = credential.enabled === false ? 0 : 1;
  const transports = credential.transports ? JSON.stringify(credential.transports) : null;
  const createdAt = Date.now();
  const data = JSON.stringify(credential);

  await db.prepare(
    `INSERT INTO credentials (uid, id, rpId, enabled, transports, createdAt, data)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
     ON CONFLICT(uid, id) DO UPDATE SET
       rpId=excluded.rpId,
       enabled=excluded.enabled,
       transports=excluded.transports,
       data=excluded.data`
  ).bind(uid, id, rpId, enabled, transports, createdAt, data).run();

  return credential;
}

export async function getCredentialsForRp(db, uid, rpId) {
  const res = await db.prepare(
    `SELECT data FROM credentials WHERE uid = ?1 AND rpId = ?2 ORDER BY createdAt DESC`
  ).bind(uid, rpId).all();

  return (res.results || []).map(r => JSON.parse(r.data));
}

export async function getCredential(db, uid, id) {
  const row = await db.prepare(`SELECT data FROM credentials WHERE uid = ?1 AND id = ?2`).bind(uid, id).first();
  return row ? JSON.parse(row.data) : null;
}

export async function deleteCredential(db, uid, id) {
  await db.prepare(`DELETE FROM credentials WHERE uid = ?1 AND id = ?2`).bind(uid, id).run();
}

export async function updateCredentialFields(db, uid, id, patchFn) {
  const current = await getCredential(db, uid, id);
  if (!current) return null;
  const next = await patchFn(current);

  const rpId = next?.metadata?.rpId;
  const enabled = next.enabled === false ? 0 : 1;
  const transports = next.transports ? JSON.stringify(next.transports) : null;
  const data = JSON.stringify(next);

  await db.prepare(
    `UPDATE credentials SET rpId=?3, enabled=?4, transports=?5, data=?6 WHERE uid=?1 AND id=?2`
  ).bind(uid, id, rpId, enabled, transports, data).run();

  return next;
}
