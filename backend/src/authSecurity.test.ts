import assert from 'node:assert/strict';
import { test } from 'node:test';
import bcrypt from 'bcryptjs';
import { canRequestOtp, canVerifyOtp, generateOtp, hashOtp, hashResetToken, normalizeEmail, normalizeName, normalizeRollNumber, secureHashEquals, studentIdentityMatches, verifyOtp } from './authSecurity';

process.env.OTP_HASH_SECRET = 'test-only-otp-hash-secret';

test('normalizes account identity fields consistently', () => {
  assert.equal(normalizeEmail('  Student@Example.COM '), 'student@example.com');
  assert.equal(normalizeName(' Rahul   Kumar '), 'rahul kumar');
  assert.equal(normalizeRollNumber(' aimt 2026 001 '), 'AIMT2026001');
});

test('requires the same account name, roll number, and email', () => {
  const account = { name: 'Rahul Kumar', rollNumber: 'AIMT2026001', email: 'rahul@example.com' };
  assert.equal(studentIdentityMatches(account, { name: ' rahul   kumar ', rollNumber: 'aimt 2026 001', email: 'RAHUL@example.com' }), true);
  assert.equal(studentIdentityMatches(account, { name: 'Wrong Name', rollNumber: account.rollNumber, email: account.email }), false);
  assert.equal(studentIdentityMatches(account, { name: account.name, rollNumber: 'OTHER2026001', email: account.email }), false);
  assert.equal(studentIdentityMatches(account, { name: account.name, rollNumber: account.rollNumber, email: 'other@example.com' }), false);
});

test('creates six digit OTPs and stores only a keyed hash', () => {
  const otp = generateOtp();
  const digest = hashOtp(otp);
  assert.match(otp, /^\d{6}$/);
  assert.notEqual(digest, otp);
  assert.equal(verifyOtp(otp, digest), true);
  const wrongOtp = otp === '000000' ? '000001' : '000000';
  assert.equal(verifyOtp(wrongOtp, digest), false);
});

test('does not accept an OTP after five failed attempts', () => {
  const expiresAt = Date.now() + 60_000;
  for (let attempts = 0; attempts < 5; attempts++) assert.equal(canVerifyOtp({ attempts, expiresAt, usedAt: null, verifiedAt: null }), true);
  assert.equal(canVerifyOtp({ attempts: 5, expiresAt, usedAt: null, verifiedAt: null }), false);
});

test('rejects expired, used, or already verified OTPs', () => {
  const now = Date.now();
  assert.equal(canVerifyOtp({ attempts: 0, expiresAt: now - 1, usedAt: null, verifiedAt: null }, now), false);
  assert.equal(canVerifyOtp({ attempts: 0, expiresAt: now + 1000, usedAt: now, verifiedAt: null }, now), false);
  assert.equal(canVerifyOtp({ attempts: 0, expiresAt: now + 1000, usedAt: null, verifiedAt: now }, now), false);
});

test('limits OTP requests to three in fifteen minutes with a resend cooldown', () => {
  const now = Date.now();
  assert.equal(canRequestOtp(0, null, now), true);
  assert.equal(canRequestOtp(2, now - 60_000, now), true);
  assert.equal(canRequestOtp(3, now - 60_000, now), false);
  assert.equal(canRequestOtp(1, now - 59_999, now), false);
});

test('reset tokens are hashed and password hashes remain one-way', async () => {
  const token = 'random-reset-token-value';
  const tokenHash = hashResetToken(token);
  assert.notEqual(tokenHash, token);
  assert.equal(secureHashEquals(tokenHash, hashResetToken(token)), true);
  assert.equal(secureHashEquals(tokenHash, hashResetToken('different-token')), false);
  const password = 'Secure-Password-123';
  const passwordHash = await bcrypt.hash(password, 12);
  assert.notEqual(passwordHash, password);
  assert.equal(await bcrypt.compare(password, passwordHash), true);
  assert.equal(await bcrypt.compare('wrong-password', passwordHash), false);
});