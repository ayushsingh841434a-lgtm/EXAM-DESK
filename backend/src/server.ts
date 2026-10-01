import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import { Prisma, PrismaClient, Role, TestStatus, AttemptStatus, ViolationType } from '@prisma/client';
import { z } from 'zod';
import { canRequestOtp, canVerifyOtp, generateOtp, hashOtp, hashResetToken, normalizeEmail, normalizeName, normalizeRollNumber, secureHashEquals, sendPasswordResetOtp, sendStudentVerificationEmail, studentIdentityMatches, verifyOtp } from './authSecurity';

const STRICT_TERMINATION_TYPES = new Set<ViolationType | string>([
  ViolationType.TAB_SWITCH,
  ViolationType.WINDOW_BLUR,
  ViolationType.FULLSCREEN_EXIT,
  'MULTIPLE_SESSION',
  'COPY_ATTEMPT',
  'PASTE_ATTEMPT',
  'CONTEXT_MENU_ATTEMPT',
]);

const TERMINATED_CHEATING = 'TERMINATED_CHEATING' as any;
const MULTIPLE_SESSION = 'MULTIPLE_SESSION' as any;

function isStrictTerminationType(type: string): boolean {
  return STRICT_TERMINATION_TYPES.has(type as ViolationType);
}

function getViolationReason(type: ViolationType | string): string {
  const normalized = String(type || 'UNKNOWN');
  return normalized;
}

const app = express();
const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const port = Number(process.env.PORT || 8080);

app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN?.split(',') || true, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(rateLimit({ windowMs: 60_000, max: 500, standardHeaders: true, legacyHeaders: false }));
const authLoginLimiter = rateLimit({ windowMs: 15 * 60_000, max: 10, standardHeaders: true, legacyHeaders: false });
if (process.env.NODE_ENV === 'production' && (!process.env.JWT_SECRET || process.env.JWT_SECRET === 'dev-secret-change-me' || !process.env.OTP_HASH_SECRET || process.env.OTP_HASH_SECRET === process.env.JWT_SECRET)) throw new Error('Distinct strong JWT_SECRET and OTP_HASH_SECRET values must be configured in production');

interface AuthReq extends Request { user?: { id: string; role: Role; email: string } }
function sign(u: any) { return jwt.sign({ id: u.id, role: u.role, email: u.email, authVersion: u.authVersion ?? 0 }, JWT_SECRET, { expiresIn: '8h' }); }
function cookieToken(req: Request): string {
  const cookie = req.headers.cookie?.split(';').map((part) => part.trim()).find((part) => part.startsWith('exam_session='));
  if (!cookie) return '';
  try { return decodeURIComponent(cookie.slice('exam_session='.length)); } catch { return ''; }
}
function setSessionCookie(res: Response, token: string) {
  res.cookie('exam_session', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/', maxAge: 8 * 60 * 60 * 1000 });
}
const clearSessionCookie = (res: Response) => res.clearCookie('exam_session', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/' });
function auth(roles?: Role[]) {
  return async (req: AuthReq, res: Response, next: NextFunction) => {
    try {
      const h = req.headers.authorization || '';
      const token = h.startsWith('Bearer ') ? h.slice(7) : cookieToken(req);
      const p: any = jwt.verify(token, JWT_SECRET);
      const sessionUser = await prisma.user.findUnique({ where: { id: p.id }, select: { id: true, role: true, email: true, status: true, authVersion: true } });
      if (!sessionUser || sessionUser.status === 'SUSPENDED' || (p.authVersion ?? 0) !== sessionUser.authVersion) return res.status(401).json({ error: 'Unauthorized' });
      if (roles && !roles.includes(sessionUser.role)) return res.status(403).json({ error: 'Forbidden' });
      req.user = { id: sessionUser.id, role: sessionUser.role, email: sessionUser.email };
      next();
    } catch { return res.status(401).json({ error: 'Unauthorized' }); }
  };
}
const admin = auth([Role.ADMIN]);
const student = auth([Role.STUDENT]);
const anyUser = auth();

const questionInput = z.object({
  questionText: z.string().min(1).max(5000),
  marks: z.coerce.number().positive(),
  negativeMarks: z.coerce.number().min(0).default(0),
  explanation: z.string().max(5000).optional().nullable(),
  options: z.array(z.object({ optionText: z.string().min(1).max(2000), isCorrect: z.boolean() })).length(4)
}).superRefine((v, ctx) => {
  if (v.options.filter(o => o.isCorrect).length !== 1) ctx.addIssue({ code: 'custom', message: 'Exactly one correct option is required', path: ['options'] });
});

async function audit(actorId: string, action: string, targetType: string, targetId: string, metadata?: unknown) {
  await prisma.auditLog.create({ data: { actorId, action, targetType, targetId, metadata: metadata as any } });
}

app.get('/health', async (_, res) => res.json({ ok: true, service: 'exam-api' }));

app.post('/api/auth/register', async (req, res) => {
  try {
    const b = z.object({ name: z.string().trim().min(2).max(100), rollNumber: z.string().trim().min(2).max(40), email: z.string().email(), password: z.string().min(8) }).parse(req.body);
    const name = b.name.replace(/\s+/g, ' ');
    const email = normalizeEmail(b.email);
    const rollNumber = normalizeRollNumber(b.rollNumber);
    const duplicate = await prisma.user.findFirst({ where: { OR: [{ email }, { rollNumber }] }, select: { email: true, rollNumber: true } });
    if (duplicate) return res.status(409).json({ error: duplicate.email === email ? 'Email already registered' : 'Roll number already registered' });
    const u = await prisma.user.create({ data: { name, email, rollNumber, passwordHash: await bcrypt.hash(b.password, 12), status: 'PENDING_VERIFICATION' } });
    const token = crypto.randomBytes(32).toString('base64url');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    await prisma.emailToken.create({ data: { userId: u.id, token: tokenHash, type: 'VERIFY', expiresAt: new Date(Date.now() + 86_400_000) } });
    if (process.env.NODE_ENV === 'production') {
      try {
        await sendStudentVerificationEmail(email, token);
      } catch {
        await prisma.user.delete({ where: { id: u.id } });
        return res.status(503).json({ error: 'Verification email could not be sent. Please try again later.' });
      }
    }
    res.status(201).json({ message: process.env.NODE_ENV === 'production' ? 'Registration complete. Check your email for a verification link before signing in.' : 'Registered. Verify the account before login.', userId: u.id, ...(process.env.NODE_ENV !== 'production' ? { devVerifyPath: `/api/auth/dev-verify/${u.id}` } : {}) });
  } catch (e: any) {
    if (e?.code === 'P2002') return res.status(409).json({ error: 'Email or roll number already registered' });
    res.status(400).json({ error: e instanceof Error ? e.message : 'Invalid request' });
  }
});

app.post('/api/auth/login', authLoginLimiter, async (req, res) => {
  const parsed = z.object({ email: z.string().trim().email(), password: z.string().min(1) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Enter a valid email and password.' });
  try {
    const b = parsed.data;
    const u = await prisma.user.findUnique({ where: { email: normalizeEmail(b.email) } });
    if (u?.role === Role.STUDENT) return res.status(400).json({ error: 'Students must sign in with name, roll number, email, and password.' });
    if (!u || !(await bcrypt.compare(b.password, u.passwordHash))) return res.status(401).json({ error: 'Invalid credentials' });
    if (u.status === 'SUSPENDED') return res.status(403).json({ error: 'Account suspended' });
    if (!u.emailVerified) return res.status(403).json({ error: 'Verify your email first' });
    const updated = await prisma.user.update({ where: { id: u.id }, data: { lastLoginAt: new Date() } });
    const token = sign(updated);
    setSessionCookie(res, token);
    res.json({ token, user: { id: u.id, name: u.name, email: u.email, role: u.role } });
  } catch {
    res.status(503).json({ error: 'Authentication service is temporarily unavailable.' });
  }
});

const resetRequestLimiter = rateLimit({ windowMs: 15 * 60_000, max: 3, standardHeaders: true, legacyHeaders: false, message: { message: 'If an account matches the information provided, an OTP has been sent to the registered email.' } });

app.post('/api/auth/student/login', authLoginLimiter, async (req, res) => {
  const parsed = z.object({ name: z.string().trim().min(1, 'Full name is required'), rollNumber: z.string().trim().min(1, 'Roll number is required'), email: z.string().trim().email('A valid email address is required'), password: z.string().min(1, 'Password is required') }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message || 'Complete all login fields.' });
  const b = parsed.data;
  const user = await prisma.user.findUnique({ where: { email: normalizeEmail(b.email) } });
  const validCredentials = !!user && user.role === Role.STUDENT && studentIdentityMatches(user, b) && await bcrypt.compare(b.password, user.passwordHash);
  if (!validCredentials || !user) return res.status(401).json({ error: 'Name, roll number, email, or password is incorrect.' });
  if (user.status === 'SUSPENDED') return res.status(403).json({ error: 'This student account is suspended. Contact your administrator.' });
  if (!user.emailVerified || user.status !== 'ACTIVE') return res.status(403).json({ error: 'Verify your student account before signing in.' });
  const updated = await prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
  const token = sign(updated);
  setSessionCookie(res, token);
  res.json({ token, user: { id: user.id, name: user.name, rollNumber: user.rollNumber, email: user.email, role: user.role } });
});

const resetIdentity = z.object({ email: z.string().trim().email(), rollNumber: z.string().trim().min(1), requestId: z.string().uuid() });
const genericResetMessage = 'If an account matches the information provided, an OTP has been sent to the registered email.';

app.post('/api/auth/forgot-password/request', resetRequestLimiter, async (req, res) => {
  const parsed = z.object({ email: z.string().trim().email(), rollNumber: z.string().trim().min(1) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Enter a valid registered email and roll number.' });
  const email = normalizeEmail(parsed.data.email);
  const rollNumber = normalizeRollNumber(parsed.data.rollNumber);
  const studentUser = await prisma.user.findFirst({ where: { email, rollNumber, role: Role.STUDENT }, select: { id: true, email: true } });
  const requestId = crypto.randomUUID();
  if (studentUser) {
    const now = new Date();
    const recent = await prisma.passwordResetOtp.count({ where: { studentId: studentUser.id, createdAt: { gte: new Date(now.getTime() - 15 * 60_000) } } });
    const latest = await prisma.passwordResetOtp.findFirst({ where: { studentId: studentUser.id }, orderBy: { createdAt: 'desc' } });
    if (canRequestOtp(recent, latest?.createdAt.getTime() ?? null, now.getTime())) {
      const otp = generateOtp();
      await prisma.$transaction([
        prisma.passwordResetOtp.updateMany({ where: { studentId: studentUser.id, usedAt: null }, data: { usedAt: now, resetTokenHash: null } }),
        prisma.passwordResetOtp.create({ data: { studentId: studentUser.id, requestId, otpHash: hashOtp(otp), expiresAt: new Date(now.getTime() + 10 * 60_000) } }),
      ]);
      try { await sendPasswordResetOtp(studentUser.email, otp); } catch { /* Keep responses identical for known and unknown accounts. */ }
    }
  }
  res.status(202).json({ message: genericResetMessage, requestId });
});

app.post('/api/auth/forgot-password/verify-otp', async (req, res) => {
  const parsed = resetIdentity.extend({ otp: z.string().regex(/^\d{6}$/, 'OTP must be 6 digits') }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid OTP request.' });
  const b = parsed.data;
  const reset = await prisma.passwordResetOtp.findUnique({ where: { requestId: b.requestId }, include: { student: true } });
  const now = new Date();
  if (!reset || reset.student.email !== normalizeEmail(b.email) || normalizeRollNumber(reset.student.rollNumber || '') !== normalizeRollNumber(b.rollNumber) || !canVerifyOtp({ attempts: reset.attempts, expiresAt: reset.expiresAt.getTime(), usedAt: reset.usedAt?.getTime() ?? null, verifiedAt: reset.verifiedAt?.getTime() ?? null }, now.getTime())) return res.status(400).json({ error: 'OTP is invalid, expired, or no longer usable.' });
  if (!verifyOtp(b.otp, reset.otpHash)) {
    await prisma.passwordResetOtp.update({ where: { id: reset.id }, data: { attempts: { increment: 1 } } });
    return res.status(400).json({ error: 'OTP is invalid, expired, or no longer usable.' });
  }
  const resetToken = crypto.randomBytes(32).toString('base64url');
  const claimed = await prisma.passwordResetOtp.updateMany({ where: { id: reset.id, attempts: { lt: 5 }, usedAt: null, verifiedAt: null, expiresAt: { gt: now } }, data: { verifiedAt: now, usedAt: now, resetTokenHash: hashResetToken(resetToken), resetExpiresAt: new Date(now.getTime() + 10 * 60_000) } });
  if (!claimed.count) return res.status(400).json({ error: 'OTP is invalid, expired, or no longer usable.' });
  res.json({ verified: true, resetToken });
});

app.post('/api/auth/forgot-password/reset', async (req, res) => {
  const parsed = resetIdentity.extend({ resetToken: z.string().min(32), password: z.string().min(8), confirmPassword: z.string().min(8) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid password reset request.' });
  const b = parsed.data;
  if (b.password !== b.confirmPassword) return res.status(400).json({ error: 'New password and confirmation do not match.' });
  const reset = await prisma.passwordResetOtp.findUnique({ where: { requestId: b.requestId }, include: { student: true } });
  if (!reset || reset.student.email !== normalizeEmail(b.email) || normalizeRollNumber(reset.student.rollNumber || '') !== normalizeRollNumber(b.rollNumber) || !reset.verifiedAt || !reset.resetTokenHash || !reset.resetExpiresAt || reset.resetExpiresAt <= new Date() || !secureHashEquals(hashResetToken(b.resetToken), reset.resetTokenHash)) return res.status(400).json({ error: 'Password reset verification is invalid or expired.' });
  if (await bcrypt.compare(b.password, reset.student.passwordHash)) return res.status(400).json({ error: 'Choose a password different from your current password.' });
  const passwordHash = await bcrypt.hash(b.password, 12);
  const now = new Date();
  const changed = await prisma.$transaction(async (tx) => {
    const claimed = await tx.passwordResetOtp.updateMany({ where: { id: reset.id, resetTokenHash: hashResetToken(b.resetToken), verifiedAt: { not: null }, resetExpiresAt: { gt: now } }, data: { resetTokenHash: null, resetExpiresAt: null } });
    if (!claimed.count) return false;
    await tx.user.update({ where: { id: reset.studentId }, data: { passwordHash, authVersion: { increment: 1 } } });
    await tx.passwordResetOtp.updateMany({ where: { studentId: reset.studentId, id: { not: reset.id }, usedAt: null }, data: { usedAt: now, resetTokenHash: null, resetExpiresAt: null } });
    return true;
  });
  if (!changed) return res.status(400).json({ error: 'Password reset verification is invalid or expired.' });
  clearSessionCookie(res);
  res.json({ reset: true, message: 'Password reset successfully. Please log in again.' });
});

app.post('/api/auth/logout', anyUser, async (req: AuthReq, res) => {
  await prisma.user.update({ where: { id: req.user!.id }, data: { authVersion: { increment: 1 } } });
  clearSessionCookie(res);
  res.status(204).end();
});

app.get('/api/auth/verify-email/:token', async (req, res) => {
  const tokenHash = crypto.createHash('sha256').update(String(req.params.token)).digest('hex');
  const token = await prisma.emailToken.findFirst({ where: { token: tokenHash, type: 'VERIFY', expiresAt: { gt: new Date() } }, select: { id: true, userId: true } });
  if (!token) return res.status(400).send('This verification link is invalid or expired.');
  await prisma.$transaction([
    prisma.user.update({ where: { id: token.userId }, data: { emailVerified: true, status: 'ACTIVE' } }),
    prisma.emailToken.delete({ where: { id: token.id } }),
  ]);
  if (process.env.FRONTEND_URL) {
    const frontendUrl = new URL(process.env.FRONTEND_URL);
    frontendUrl.searchParams.set('verified', '1');
    return res.redirect(frontendUrl.toString());
  }
  res.send('Email verified. Return to the exam platform and sign in.');
});

app.get('/api/auth/dev-verify/:userId', async (req, res) => {
  if (process.env.NODE_ENV === 'production') return res.status(404).end();
  const user = await prisma.user.findUnique({ where: { id: req.params.userId }, select: { id: true, emailVerified: true, status: true } });
  if (!user) return res.status(404).json({ error: 'Account not found' });
  if (user.emailVerified && user.status === 'ACTIVE') return res.json({ verified: true, alreadyVerified: true });
  const tok = await prisma.emailToken.findFirst({ where: { userId: req.params.userId, type: 'VERIFY', expiresAt: { gt: new Date() } } });
  if (!tok) return res.status(404).json({ error: 'Token not found' });
  await prisma.user.update({ where: { id: req.params.userId }, data: { emailVerified: true, status: 'ACTIVE' } });
  await prisma.emailToken.delete({ where: { id: tok.id } });
  res.json({ verified: true });
});

app.get('/api/me', anyUser, async (req: AuthReq, res) => {
  const u = await prisma.user.findUnique({ where: { id: req.user!.id }, select: { id: true, name: true, rollNumber: true, email: true, role: true, status: true } });
  res.json(u);
});

// ---------------- Admin: tests ----------------
app.get('/api/tests', anyUser, async (req: AuthReq, res) => {
  const now = new Date();
  const where = req.user!.role === Role.ADMIN ? {} : { status: TestStatus.LIVE, startTime: { lte: now }, endTime: { gte: now } };
  const tests = await prisma.test.findMany({ where, include: { _count: { select: { questions: true, attempts: true } } }, orderBy: { createdAt: 'desc' } });
  res.json(tests);
});

app.post('/api/tests', admin, async (req: AuthReq, res: Response) => {
  try {
    const b = z.object({
      title: z.string().min(1).max(200), description: z.string().max(2000).optional(), duration: z.coerce.number().int().positive(),
      startTime: z.string(), endTime: z.string(), violationLimit: z.coerce.number().int().min(1).max(20).default(3), maxAttempts: z.coerce.number().int().min(1).max(10).default(1)
    }).parse(req.body);
    const t = await prisma.test.create({ data: { title: b.title, description: b.description, duration: b.duration, startTime: new Date(b.startTime), endTime: new Date(b.endTime), violationLimit: b.violationLimit, maxAttempts: b.maxAttempts } });
    await audit(req.user!.id, 'CREATE', 'TEST', t.id);
    res.status(201).json(t);
  } catch (e) { res.status(400).json({ error: e instanceof Error ? e.message : 'Invalid request' }); }
});

app.patch('/api/tests/:id', admin, async (req: AuthReq, res: Response) => {
  try {
    const b = z.object({ title: z.string().min(1).max(200), description: z.string().max(2000).optional().nullable(), duration: z.coerce.number().int().positive(), startTime: z.string(), endTime: z.string(), violationLimit: z.coerce.number().int().min(1).max(20), maxAttempts: z.coerce.number().int().min(1).max(10) }).parse(req.body);
    const id = String(req.params.id);
    const t = await prisma.test.update({ where: { id }, data: { ...b, startTime: new Date(b.startTime), endTime: new Date(b.endTime) } });
    await audit(req.user!.id, 'UPDATE', 'TEST', t.id);
    res.json(t);
  } catch (e) { res.status(400).json({ error: e instanceof Error ? e.message : 'Invalid request' }); }
});

app.delete('/api/tests/:id', admin, async (req: AuthReq, res: Response) => {
  const id = String(req.params.id);
  const attempts = await prisma.attempt.count({ where: { testId: id } });
  if (attempts) return res.status(409).json({ error: 'This test has attempts/results and cannot be deleted. End it instead.' });
  await prisma.test.delete({ where: { id } });
  await audit(req.user!.id, 'DELETE', 'TEST', id);
  res.json({ deleted: true });
});

app.patch('/api/tests/:id/status', admin, async (req: AuthReq, res: Response) => {
  try {
    const id = String(req.params.id);
    const status = z.enum(['DRAFT', 'LIVE', 'PAUSED', 'ENDED']).parse(req.body.status);
    const t = await prisma.test.update({ where: { id }, data: { status } });
    await audit(req.user!.id, `STATUS_${status}`, 'TEST', t.id);
    res.json(t);
  } catch { res.status(400).json({ error: 'Invalid status' }); }
});

// ---------------- Admin: questions ----------------
app.get('/api/admin/tests/:testId/questions', admin, async (req: AuthReq, res: Response) => {
  const testId = String(req.params.testId);
  const qs = await prisma.question.findMany({ where: { testId }, orderBy: { order: 'asc' }, include: { options: { orderBy: { order: 'asc' } } } });
  res.json(qs);
});

app.post('/api/tests/:testId/questions', admin, async (req: AuthReq, res: Response) => {
  try {
    const b = questionInput.parse(req.body);
    const testId = String(req.params.testId);
    const max = await prisma.question.aggregate({ where: { testId }, _max: { order: true } });
    const q = await prisma.question.create({ data: { testId, questionText: b.questionText, marks: b.marks, negativeMarks: b.negativeMarks, explanation: b.explanation || undefined, order: (max._max.order ?? -1) + 1, options: { create: b.options.map((o, i) => ({ ...o, order: i })) } }, include: { options: true } });
    await audit(req.user!.id, 'CREATE', 'QUESTION', q.id, { testId });
    res.status(201).json(q);
  } catch (e) { res.status(400).json({ error: e instanceof Error ? e.message : 'Invalid question' }); }
});

app.patch('/api/questions/:id', admin, async (req: AuthReq, res: Response) => {
  try {
    const b = questionInput.parse(req.body);
    const id = String(req.params.id);
    const existing = await prisma.question.findUnique({ where: { id }, include: { answers: { take: 1 } } });
    if (!existing) return res.status(404).json({ error: 'Question not found' });
    if (existing.answers.length) return res.status(409).json({ error: 'This question has student answers and cannot be edited. Create a new version instead.' });
    const q = await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
      await tx.option.deleteMany({ where: { questionId: id } });
      return tx.question.update({ where: { id }, data: { questionText: b.questionText, marks: b.marks, negativeMarks: b.negativeMarks, explanation: b.explanation || null, options: { create: b.options.map((o, i) => ({ ...o, order: i })) } }, include: { options: true } });
    });
    await audit(req.user!.id, 'UPDATE', 'QUESTION', q.id);
    res.json(q);
  } catch (e) { res.status(400).json({ error: e instanceof Error ? e.message : 'Invalid question' }); }
});

app.delete('/api/questions/:id', admin, async (req: AuthReq, res: Response) => {
  const id = String(req.params.id);
  const q = await prisma.question.findUnique({ where: { id }, include: { _count: { select: { answers: true } } } });
  if (!q) return res.status(404).json({ error: 'Question not found' });
  if (q._count.answers) return res.status(409).json({ error: 'This question has student answers and cannot be deleted.' });
  await prisma.question.delete({ where: { id } });
  await audit(req.user!.id, 'DELETE', 'QUESTION', id);
  res.json({ deleted: true });
});

// ---------------- Student attempts ----------------
app.post('/api/attempts/start', student, async (req: AuthReq, res) => {
  try {
    const { testId } = z.object({ testId: z.string().uuid() }).parse(req.body);
    const t = await prisma.test.findUnique({ where: { id: testId }, include: { questions: { select: { id: true } } } });
    if (!t || t.status !== TestStatus.LIVE) return res.status(400).json({ error: 'Test is not available' });
    const now = new Date();
    if (now < t.startTime || now > t.endTime) return res.status(400).json({ error: 'Outside test window' });
    if (!t.questions.length) return res.status(400).json({ error: 'This test has no questions yet' });
    const used = await prisma.attempt.count({ where: { testId, userId: req.user!.id, status: { in: [AttemptStatus.SUBMITTED, AttemptStatus.AUTO_SUBMITTED, AttemptStatus.CANCELLED_VIOLATION, TERMINATED_CHEATING] } } });
    if (used >= t.maxAttempts) return res.status(409).json({ error: 'Maximum attempts reached' });
    const existing = await prisma.attempt.findFirst({ where: { testId, userId: req.user!.id, status: AttemptStatus.IN_PROGRESS } });
    if (existing) return res.json({ id: existing.id, status: existing.status, terminated: existing.status === TERMINATED_CHEATING });
    const attempt = await (prisma.attempt as any).create({ data: { testId, userId: req.user!.id, status: AttemptStatus.IN_PROGRESS, startedAt: now, serverEndsAt: new Date(now.getTime() + t.duration * 60_000), questionOrderSeed: Math.floor(Math.random() * 1_000_000_000), sessionToken: crypto.randomUUID(), heartbeatAt: now } as any });
    res.status(201).json({ id: attempt.id, status: attempt.status, sessionToken: (attempt as any).sessionToken });
  } catch (e) { res.status(400).json({ error: e instanceof Error ? e.message : 'Invalid request' }); }
});

function shuffle<T>(items: T[], seed: number): T[] {
  const out = [...items]; let x = seed || 1;
  for (let i = out.length - 1; i > 0; i--) { x = (x * 1664525 + 1013904223) % 4294967296; const j = Math.floor((x / 4294967296) * (i + 1)); [out[i], out[j]] = [out[j], out[i]]; }
  return out;
}

app.get('/api/attempts/:id', student, async (req: AuthReq, res: Response) => {
  const id = String(req.params.id);
  const a = await prisma.attempt.findFirst({ where: { id, userId: req.user!.id }, include: { test: true, answers: true } });
  if (!a) return res.status(404).json({ error: 'Attempt not found' });
  if ((a as any).status === TERMINATED_CHEATING) {
    return res.status(403).json({ error: 'Attempt terminated for cheating', terminated: true, terminationReason: (a as any).terminationReason, attemptId: a.id });
  }
  const qs = await prisma.question.findMany({ where: { testId: a.testId }, include: { options: { select: { id: true, optionText: true, order: true } } }, orderBy: { order: 'asc' } });
  const questions = shuffle(qs, a.questionOrderSeed).map((q) => ({ ...q, options: shuffle(q.options, a.questionOrderSeed + q.id.length) }));
  const remainingSeconds = a.serverEndsAt ? Math.max(0, Math.floor((a.serverEndsAt.getTime() - Date.now()) / 1000)) : 0;
  if (a.status === AttemptStatus.IN_PROGRESS && remainingSeconds === 0) await submitAttempt(a.id, AttemptStatus.AUTO_SUBMITTED);
  res.json({ id: a.id, status: a.status, score: a.score, violationCount: a.violationCount, serverEndsAt: a.serverEndsAt, remainingSeconds, terminationReason: (a as any).terminationReason, sessionToken: (a as any).sessionToken, test: { id: a.test.id, title: a.test.title, duration: a.test.duration, violationLimit: a.test.violationLimit }, questions, answers: a.answers.map((x) => ({ questionId: x.questionId, selectedOptionId: x.selectedOptionId })) });
});

app.put('/api/attempts/:id/answers', student, async (req: AuthReq, res: Response) => {
  try {
    const b = z.object({ questionId: z.string().uuid(), selectedOptionId: z.string().uuid().nullable() }).parse(req.body);
    const id = String(req.params.id);
    const a = await prisma.attempt.findFirst({ where: { id, userId: req.user!.id, status: AttemptStatus.IN_PROGRESS } });
    if (!a) return res.status(400).json({ error: 'Attempt is not active' });
    if (a.serverEndsAt && a.serverEndsAt <= new Date()) return res.status(400).json({ error: 'Time expired' });
    const q = await prisma.question.findFirst({ where: { id: b.questionId, testId: a.testId } });
    if (!q) return res.status(400).json({ error: 'Invalid question' });
    if (b.selectedOptionId) { const opt = await prisma.option.findFirst({ where: { id: b.selectedOptionId, questionId: q.id } }); if (!opt) return res.status(400).json({ error: 'Invalid option' }); }
    const answer = await prisma.answer.upsert({ where: { attemptId_questionId: { attemptId: a.id, questionId: q.id } }, update: { selectedOptionId: b.selectedOptionId }, create: { attemptId: a.id, questionId: q.id, selectedOptionId: b.selectedOptionId } });
    res.json({ saved: true, id: answer.id });
  } catch { res.status(400).json({ error: 'Invalid answer' }); }
});

async function submitAttempt(id: string, status: AttemptStatus = AttemptStatus.SUBMITTED) {
  return prisma.$transaction(async (tx: Prisma.TransactionClient) => {
    const a = await tx.attempt.findUnique({ where: { id }, include: { test: true, answers: { include: { selectedOption: true, question: true } } } });
    if (!a) throw new Error('Attempt not found');
    if (!([AttemptStatus.IN_PROGRESS, AttemptStatus.NOT_STARTED] as AttemptStatus[]).includes(a.status)) return a;
    let score = 0;
    for (const answer of a.answers) {
      if (answer.selectedOption?.isCorrect) score += answer.question.marks;
      else if (answer.selectedOption && a.test.negativeMarking) score -= answer.question.negativeMarks;
    }
    const changed = await tx.attempt.updateMany({ where: { id, status: { in: [AttemptStatus.IN_PROGRESS, AttemptStatus.NOT_STARTED] } }, data: { status, score, submittedAt: new Date() } });
    if (changed.count === 0) return (await tx.attempt.findUnique({ where: { id } }))!;
    return (await tx.attempt.findUnique({ where: { id } }))!;
  });
}

app.post('/api/attempts/:id/submit', student, async (req: AuthReq, res: Response) => {
  const id = String(req.params.id);
  const a = await prisma.attempt.findFirst({ where: { id, userId: req.user!.id } });
  if (!a) return res.status(404).json({ error: 'Attempt not found' });
  const r = await submitAttempt(a.id);
  res.json(r);
});

app.post('/api/attempts/:id/violations', student, async (req: AuthReq, res: Response) => {
  try {
    const b = z.object({ type: z.enum(['TAB_SWITCH', 'WINDOW_BLUR', 'FULLSCREEN_EXIT', 'COPY_PASTE_ATTEMPT', 'DEVTOOLS_SUSPECTED', 'PRINT_ATTEMPT', 'COPY_ATTEMPT', 'PASTE_ATTEMPT', 'CONTEXT_MENU_ATTEMPT', 'MULTIPLE_SESSION']).default('TAB_SWITCH'), metadata: z.any().optional(), sessionToken: z.string().optional() }).parse(req.body);
    const id = String(req.params.id);
    const a = await prisma.attempt.findFirst({ where: { id, userId: req.user!.id }, include: { test: true } });
    if (!a) return res.status(404).json({ error: 'Attempt not found' });
    if (a.status !== AttemptStatus.IN_PROGRESS) return res.status(400).json({ error: 'Attempt not active' });
    if (b.sessionToken && b.sessionToken !== (a as any).sessionToken) {
      await (prisma.attempt as any).update({ where: { id: a.id }, data: { status: TERMINATED_CHEATING, terminationReason: 'MULTIPLE_SESSION', violationCount: { increment: 1 }, heartbeatAt: new Date() } as any });
      await (prisma.examViolation as any).create({ data: { attemptId: a.id, studentId: a.userId, type: MULTIPLE_SESSION, metadata: { ...b.metadata, sessionToken: b.sessionToken, reason: 'MULTIPLE_SESSION' } } as any });
      return res.json({ violationCount: a.violationCount + 1, cancelled: true, terminated: true, reason: 'MULTIPLE_SESSION' });
    }
    const violationType = b.type as any;
    await (prisma.examViolation as any).create({ data: { attemptId: a.id, studentId: a.userId, type: violationType, metadata: b.metadata || {} } as any });
    const updated = await (prisma.attempt as any).update({ where: { id: a.id }, data: { violationCount: { increment: 1 }, heartbeatAt: new Date() } as any });
    const strict = isStrictTerminationType(violationType);
    if (strict) {
      const terminated = await (prisma.attempt as any).update({ where: { id: a.id }, data: { status: TERMINATED_CHEATING, terminationReason: getViolationReason(violationType), violationCount: updated.violationCount, submittedAt: new Date(), heartbeatAt: new Date() } as any });
      return res.json({ violationCount: terminated.violationCount, cancelled: true, terminated: true, reason: getViolationReason(violationType) });
    }
    const cancelled = updated.violationCount >= a.test.violationLimit;
    if (cancelled) {
      const ended = await (prisma.attempt as any).update({ where: { id: a.id }, data: { status: AttemptStatus.CANCELLED_VIOLATION, terminationReason: 'VIOLATION_LIMIT', submittedAt: new Date() } as any });
      return res.json({ violationCount: ended.violationCount, cancelled: true, terminated: false, reason: 'VIOLATION_LIMIT' });
    }
    res.json({ violationCount: updated.violationCount, cancelled: false, terminated: false, reason: getViolationReason(violationType) });
  } catch (e) { res.status(400).json({ error: e instanceof Error ? e.message : 'Invalid violation' }); }
});

// ---------------- Admin monitoring/results ----------------
app.get('/api/admin/monitor', admin, async (_, res) => {
  const active = await prisma.attempt.findMany({ where: { status: AttemptStatus.IN_PROGRESS }, include: { user: { select: { id: true, name: true, email: true } }, test: { select: { id: true, title: true, violationLimit: true } } }, orderBy: { startedAt: 'desc' }, take: 1000 });
  res.json(active.map(a => ({ ...a, remainingSeconds: a.serverEndsAt ? Math.max(0, Math.floor((a.serverEndsAt.getTime() - Date.now()) / 1000)) : 0 })));
});

app.get('/api/admin/results', admin, async (req, res) => {
  const testId = typeof req.query.testId === 'string' ? req.query.testId : undefined;
  const rows = await prisma.attempt.findMany({ where: { ...(testId ? { testId } : {}), status: { in: [AttemptStatus.SUBMITTED, AttemptStatus.AUTO_SUBMITTED, AttemptStatus.CANCELLED_VIOLATION, TERMINATED_CHEATING] } } as any, include: { user: { select: { id: true, name: true, email: true } }, test: { select: { id: true, title: true, duration: true } }, answers: { include: { selectedOption: true, question: { include: { options: true } } } }, violations: true }, orderBy: [{ testId: 'asc' }, { score: 'desc' }, { submittedAt: 'asc' }], take: 5000 });
  res.json(rows.map((a: any) => ({ id: a.id, student: a.user, test: a.test, status: a.status, score: a.score, submittedAt: a.submittedAt, startedAt: a.startedAt, violationCount: a.violationCount, terminationReason: a.terminationReason, violations: a.violations.map((v: any) => ({ type: v.type, timestamp: v.timestamp, metadata: v.metadata })), correct: a.answers.filter((x: any) => !!x.selectedOption?.isCorrect).length, wrong: a.answers.filter((x: any) => !!x.selectedOption && !x.selectedOption.isCorrect).length, skipped: a.answers.filter((x: any) => !x.selectedOption).length })));
});

app.get('/api/admin/results/:attemptId', admin, async (req: AuthReq, res: Response) => {
  const attemptId = String(req.params.attemptId);
  const a = await prisma.attempt.findUnique({ where: { id: attemptId }, include: { user: { select: { id: true, name: true, email: true } }, test: true, answers: { include: { selectedOption: true } }, violations: true } });
  if (!a) return res.status(404).json({ error: 'Result not found' });
  const qs = await prisma.question.findMany({ where: { testId: a.testId }, include: { options: true }, orderBy: { order: 'asc' } });
  const answerMap = new Map<string, (typeof a.answers)[number]>(a.answers.map((x) => [x.questionId, x]));
  res.json({ id: a.id, student: a.user, test: a.test, status: a.status, score: a.score, startedAt: a.startedAt, submittedAt: a.submittedAt, violationCount: a.violationCount, terminationReason: (a as any).terminationReason, violations: a.violations, questions: qs.map((q) => { const x = answerMap.get(q.id); const correct = q.options.find((o) => o.isCorrect); return { questionId: q.id, questionText: q.questionText, marks: q.marks, negativeMarks: q.negativeMarks, selectedOptionId: x?.selectedOptionId || null, selectedOptionText: x?.selectedOption?.optionText || null, correctOptionId: correct?.id || null, correctOptionText: correct?.optionText || null, isCorrect: !!x?.selectedOption?.isCorrect, explanation: q.explanation }; }) });
});

app.get('/api/admin/stats', admin, async (_, res) => {
  const [students, tests, active, completed] = await Promise.all([
    prisma.user.count({ where: { role: Role.STUDENT } }), prisma.test.count(), prisma.attempt.count({ where: { status: AttemptStatus.IN_PROGRESS } }), prisma.attempt.count({ where: { status: { in: [AttemptStatus.SUBMITTED, AttemptStatus.AUTO_SUBMITTED, AttemptStatus.CANCELLED_VIOLATION, TERMINATED_CHEATING] } } as any })
  ]);
  res.json({ students, tests, active, completed });
});

app.get('/api/admin/students', admin, async (_req, res) => {
  const students = await prisma.user.findMany({
    where: { role: Role.STUDENT },
    select: { id: true, name: true, rollNumber: true, email: true, status: true, createdAt: true, lastLoginAt: true },
    orderBy: [{ createdAt: 'desc' }],
    take: 5000,
  });
  res.json(students);
});

app.use((err: any, _req: Request, res: Response, _next: NextFunction) => res.status(500).json({ error: 'Internal server error' }));
app.listen(port, () => console.log(`Exam API listening on ${port}`));
