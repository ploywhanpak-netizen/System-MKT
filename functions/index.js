const functions = require('firebase-functions');
const admin = require('firebase-admin');
admin.initializeApp();

const db = admin.firestore();
const VALID_ROLES = ['requester', 'approver', 'admin'];

// Basic brute-force throttle: max 8 failed attempts per source IP per 10 minutes.
// A 4-digit code only has 10,000 combinations, so this is a hard requirement,
// not a nice-to-have - without it the code could be guessed by scripting the
// callable function directly.
const MAX_FAILED_ATTEMPTS = 8;
const WINDOW_MS = 10 * 60 * 1000;

function getClientIp(context) {
  const forwarded = context.rawRequest?.headers?.['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length) return forwarded.split(',')[0].trim();
  return context.rawRequest?.ip || 'unknown';
}

async function checkAndRecordAttempt(ip, failed) {
  const ref = db.collection('codeAttempts').doc(ip);
  await db.runTransaction(async tx => {
    const snap = await tx.get(ref);
    const now = Date.now();
    let data = snap.exists ? snap.data() : { count: 0, windowStart: now };
    if (now - (data.windowStart || 0) > WINDOW_MS) data = { count: 0, windowStart: now };
    if (data.count >= MAX_FAILED_ATTEMPTS) {
      throw new functions.https.HttpsError('resource-exhausted', 'ลองผิดหลายครั้งเกินไป กรุณารอสักครู่แล้วลองใหม่');
    }
    if (failed) {
      tx.set(ref, { count: (data.count || 0) + 1, windowStart: data.windowStart, updatedAt: admin.firestore.FieldValue.serverTimestamp() });
    } else if (snap.exists) {
      tx.set(ref, { count: 0, windowStart: now, updatedAt: admin.firestore.FieldValue.serverTimestamp() });
    }
  });
}

exports.verifyAccessCode = functions.https.onCall(async (data, context) => {
  const code = String(data && data.code || '').trim();
  const ip = getClientIp(context);

  if (!/^\d{4}$/.test(code)) {
    throw new functions.https.HttpsError('invalid-argument', 'กรุณากรอกรหัส 4 หลัก');
  }

  // Throttle check happens before the lookup so a flood of guesses still costs a write.
  await checkAndRecordAttempt(ip, false);

  const snap = await db.collection('accessCodes').doc(code).get();
  if (!snap.exists) {
    await checkAndRecordAttempt(ip, true);
    throw new functions.https.HttpsError('permission-denied', 'รหัสไม่ถูกต้อง');
  }

  const record = snap.data() || {};
  if (record.active === false) {
    await checkAndRecordAttempt(ip, true);
    throw new functions.https.HttpsError('permission-denied', 'รหัสนี้ถูกระงับการใช้งาน');
  }

  const role = VALID_ROLES.includes(record.role) ? record.role : 'requester';
  const uid = `code-${code}`;

  await snap.ref.set({ lastUsedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });

  const token = await admin.auth().createCustomToken(uid, {
    role,
    name: record.name || '',
    codeAccess: true,
  });

  return { token, role, name: record.name || '' };
});
