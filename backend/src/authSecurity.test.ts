import assert from 'node:assert/strict';
import { test } from 'node:test';
import bcrypt from 'bcryptjs';
import { canRequestOtp, canVerifyOtp, generateOtp, hashOtp, hashResetToken, missingEmailConfiguration, normalizeEmail, normalizeName, normalizeRollNumber, secureHashEquals, sendEmail, sendStudentVerificationEmail, studentIdentityMatches, verifyOtp } from './authSecurity';

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

test('reports missing email configuration without requiring or exposing values', () => {
  assert.deepEqual(missingEmailConfiguration({}), ['GOOGLE_APPS_SCRIPT_EMAIL_URL', 'API_PUBLIC_URL']);
  assert.deepEqual(missingEmailConfiguration({
    GOOGLE_APPS_SCRIPT_EMAIL_URL: 'https://email-handler.example.invalid/exec',
    API_PUBLIC_URL: 'https://exam.example.invalid',
  }), []);
});

test('sends email through the shared provider without logging message contents', async () => {
  const previousUrl = process.env.GOOGLE_APPS_SCRIPT_EMAIL_URL;
  const originalFetch = globalThis.fetch;
  let requestBody = '';
  process.env.GOOGLE_APPS_SCRIPT_EMAIL_URL = 'https://email-handler.example.invalid/exec';
  globalThis.fetch = async (_input, init) => {
    requestBody = String(init?.body || '');
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  };

  try {
    await sendEmail('student@example.invalid', 'Password reset', 'Test-only OTP content');
    assert.deepEqual(JSON.parse(requestBody), {
      to: 'student@example.invalid',
      subject: 'Password reset',
      text: 'Test-only OTP content',
    });
  } finally {
    globalThis.fetch = originalFetch;
    if (previousUrl === undefined) delete process.env.GOOGLE_APPS_SCRIPT_EMAIL_URL;
    else process.env.GOOGLE_APPS_SCRIPT_EMAIL_URL = previousUrl;
  }
});

test('reports provider failure without including response body content', async () => {
  const previousUrl = process.env.GOOGLE_APPS_SCRIPT_EMAIL_URL;
  const originalFetch = globalThis.fetch;
  process.env.GOOGLE_APPS_SCRIPT_EMAIL_URL = 'https://email-handler.example.invalid/exec';
  globalThis.fetch = async () => new Response('private response content', { status: 503 });

  try {
    await assert.rejects(sendEmail('student@example.invalid', 'Password reset', 'Test-only OTP content'), (error: Error) => {
      assert.equal(error.message, 'Email provider request failed with status 503.');
      assert.equal(error.message.includes('private response content'), false);
      return true;
    });
  } finally {
    globalThis.fetch = originalFetch;
    if (previousUrl === undefined) delete process.env.GOOGLE_APPS_SCRIPT_EMAIL_URL;
    else process.env.GOOGLE_APPS_SCRIPT_EMAIL_URL = previousUrl;
  }
});

test('continues to send verification links through the shared provider', async () => {
  const previousUrl = process.env.GOOGLE_APPS_SCRIPT_EMAIL_URL;
  const previousPublicUrl = process.env.API_PUBLIC_URL;
  const originalFetch = globalThis.fetch;
  let requestBody = '';
  process.env.GOOGLE_APPS_SCRIPT_EMAIL_URL = 'https://email-handler.example.invalid/exec';
  process.env.API_PUBLIC_URL = 'https://exam.example.invalid/';
  globalThis.fetch = async (_input, init) => {
    requestBody = String(init?.body || '');
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  };

  try {
    await sendStudentVerificationEmail('student@example.invalid', 'test-verification-token');
    const sent = JSON.parse(requestBody);
    assert.equal(sent.to, 'student@example.invalid');
    assert.equal(sent.subject, 'Exam Platform - Verify your email');
    assert.match(sent.text, /https:\/\/exam\.example\.invalid\/api\/auth\/verify-email\/test-verification-token/);
  } finally {
    globalThis.fetch = originalFetch;
    if (previousUrl === undefined) delete process.env.GOOGLE_APPS_SCRIPT_EMAIL_URL;
    else process.env.GOOGLE_APPS_SCRIPT_EMAIL_URL = previousUrl;
    if (previousPublicUrl === undefined) delete process.env.API_PUBLIC_URL;
    else process.env.API_PUBLIC_URL = previousPublicUrl;
  }
});