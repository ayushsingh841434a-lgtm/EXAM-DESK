import crypto from 'crypto';

export function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

export function normalizeName(value: string): string {
  return value.trim().replace(/\s+/g, ' ').toLowerCase();
}

export function normalizeRollNumber(value: string): string {
  return value.trim().replace(/\s+/g, '').toUpperCase();
}

export function studentIdentityMatches(account: { name: string; rollNumber: string | null; email: string }, input: { name: string; rollNumber: string; email: string }): boolean {
  return normalizeName(account.name) === normalizeName(input.name)
    && normalizeRollNumber(account.rollNumber || '') === normalizeRollNumber(input.rollNumber)
    && normalizeEmail(account.email) === normalizeEmail(input.email);
}

export function generateOtp(): string {
  return crypto.randomInt(0, 1_000_000).toString().padStart(6, '0');
}

export function hashOtp(otp: string): string {
  const secret = process.env.OTP_HASH_SECRET || process.env.JWT_SECRET;
  if (!secret) throw new Error('OTP_HASH_SECRET or JWT_SECRET must be configured');
  return crypto.createHmac('sha256', secret).update(otp).digest('hex');
}

export function verifyOtp(otp: string, expectedHash: string): boolean {
  const actual = Buffer.from(hashOtp(otp), 'hex');
  const expected = Buffer.from(expectedHash, 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

export function hashResetToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export function secureHashEquals(actualHex: string, expectedHex: string): boolean {
  const actual = Buffer.from(actualHex, 'hex');
  const expected = Buffer.from(expectedHex, 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

export function canRequestOtp(recentRequests: number, lastRequestedAt: number | null, now = Date.now()): boolean {
  return recentRequests < 3 && (lastRequestedAt === null || now - lastRequestedAt >= 60_000);
}

export function canVerifyOtp(input: { attempts: number; expiresAt: number; usedAt: number | null; verifiedAt: number | null }, now = Date.now()): boolean {
  return input.attempts < 5 && input.expiresAt > now && input.usedAt === null && input.verifiedAt === null;
}

export function missingEmailConfiguration(env: NodeJS.ProcessEnv = process.env): string[] {
  return ['GOOGLE_APPS_SCRIPT_EMAIL_URL', 'API_PUBLIC_URL'].filter((name) => !env[name]?.trim());
}

export async function sendEmail(recipient: string, subject: string, text: string): Promise<void> {
  const { GOOGLE_APPS_SCRIPT_EMAIL_URL } = process.env;
  const endpoint = GOOGLE_APPS_SCRIPT_EMAIL_URL?.trim();
  if (!endpoint) {
    throw new Error('Email configuration is incomplete: GOOGLE_APPS_SCRIPT_EMAIL_URL is missing.');
  }

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ to: recipient, subject, text }),
  });

  if (!response.ok) {
    throw new Error(`Email provider request failed with status ${response.status}.`);
  }

  const result = await response.json().catch(() => null);
  if (result && result.ok === false) {
    throw new Error('Email provider reported a delivery failure.');
  }
}

export async function sendPasswordResetOtp(email: string, otp: string): Promise<void> {
  await sendEmail(
    email,
    'Exam Platform - Password Reset OTP',
    `Your password reset OTP is: ${otp}\n\nThis OTP will expire in 10 minutes.\n\nIf you did not request a password reset, ignore this email.`,
  );
}

export async function sendStudentVerificationEmail(email: string, token: string): Promise<void> {
  const { API_PUBLIC_URL } = process.env;
  if (!API_PUBLIC_URL?.trim()) {
    throw new Error('Email configuration is incomplete: API_PUBLIC_URL is missing.');
  }

  const verificationUrl = `${API_PUBLIC_URL.trim().replace(/\/$/, '')}/api/auth/verify-email/${encodeURIComponent(token)}`;
  const emailBody = `Verify your student account by opening this link:\n\n${verificationUrl}\n\nThis link expires in 24 hours.`;
  await sendEmail(email, 'Exam Platform - Verify your email', emailBody);
}