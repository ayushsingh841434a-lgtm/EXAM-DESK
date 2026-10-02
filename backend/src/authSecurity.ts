import crypto from 'crypto';
import nodemailer from 'nodemailer';

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

export async function sendPasswordResetOtp(email: string, otp: string): Promise<void> {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM } = process.env;
  if (!SMTP_HOST || !SMTP_PORT || !SMTP_FROM) throw new Error('SMTP_HOST, SMTP_PORT, and SMTP_FROM must be configured');

  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: process.env.SMTP_SECURE === 'true',
    ...(SMTP_USER && SMTP_PASSWORD ? { auth: { user: SMTP_USER, pass: SMTP_PASSWORD } } : {}),
  });

  await transporter.sendMail({
    from: SMTP_FROM,
    to: email,
    subject: 'Exam Platform - Password Reset OTP',
    text: `Your password reset OTP is: ${otp}\n\nThis OTP will expire in 10 minutes.\n\nIf you did not request a password reset, ignore this email.`,
  });
}

export async function sendStudentVerificationEmail(email: string, token: string): Promise<void> {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM, API_PUBLIC_URL } = process.env;
  if (!SMTP_HOST || !SMTP_PORT || !SMTP_FROM || !API_PUBLIC_URL) {
    throw new Error('SMTP_HOST, SMTP_PORT, SMTP_FROM, and API_PUBLIC_URL must be configured');
  }

  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: process.env.SMTP_SECURE === 'true',
    family: 4,
    ...(SMTP_USER && SMTP_PASSWORD ? { auth: { user: SMTP_USER, pass: SMTP_PASSWORD } } : {}),
  } as any);
  const verificationUrl = `${API_PUBLIC_URL.replace(/\/$/, '')}/api/auth/verify-email/${encodeURIComponent(token)}`;

  await transporter.sendMail({
    from: SMTP_FROM,
    to: email,
    subject: 'Exam Platform - Verify your email',
    text: `Verify your student account by opening this link:\n\n${verificationUrl}\n\nThis link expires in 24 hours.`,
  });
}