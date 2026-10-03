import assert from 'node:assert/strict';
import { test } from 'node:test';
import bcrypt from 'bcryptjs';

test('forgot-password responses stay generic and successful reset hashes password and invalidates sessions', async () => {
  process.env.NODE_ENV = 'test';
  process.env.JWT_SECRET = 'test-only-jwt-secret';
  process.env.OTP_HASH_SECRET = 'test-only-otp-secret';
  process.env.GOOGLE_APPS_SCRIPT_EMAIL_URL = 'https://email-handler.example.invalid/exec';
  process.env.API_PUBLIC_URL = 'https://exam.example.invalid';

  const { app, prisma } = await import('./server.js');
  const originalFetch = globalThis.fetch;
  const restorers: Array<() => void> = [];
  const providerOtpByEmail = new Map<string, string>();
  let failEmailProvider = false;
  let records: Array<Record<string, any>> = [];

  const users = [
    {
      id: 'reset-student-id',
      name: 'Test Student',
      email: 'student@example.invalid',
      rollNumber: 'TEST-001',
      passwordHash: await bcrypt.hash('Old-password-123', 4),
      role: 'STUDENT',
      status: 'ACTIVE',
      emailVerified: true,
      authVersion: 0,
      lastLoginAt: null as Date | null,
    },
    {
      id: 'delivery-failure-student-id',
      name: 'Delivery Failure Student',
      email: 'delivery-failure@example.invalid',
      rollNumber: 'TEST-002',
      passwordHash: await bcrypt.hash('Old-password-456', 4),
      role: 'STUDENT',
      status: 'ACTIVE',
      emailVerified: true,
      authVersion: 0,
      lastLoginAt: null as Date | null,
    },
  ];

  function replaceMethod(target: object, key: string, implementation: (...args: any[]) => any) {
    const original = Object.getOwnPropertyDescriptor(target, key);
    Object.defineProperty(target, key, { configurable: true, writable: true, value: implementation });
    restorers.push(() => {
      if (original) Object.defineProperty(target, key, original);
      else Reflect.deleteProperty(target, key);
    });
  }

  function updateOtpMany(args: any) {
    const row = records.find((candidate) => candidate.id === args.where.id);
    if (!row) return { count: 0 };
    if (args.where.attempts && row.attempts >= args.where.attempts.lt) return { count: 0 };
    if (args.where.usedAt === null && row.usedAt !== null) return { count: 0 };
    if (args.where.verifiedAt === null && row.verifiedAt !== null) return { count: 0 };
    if (args.where.expiresAt?.gt && row.expiresAt <= args.where.expiresAt.gt) return { count: 0 };
    Object.assign(row, args.data);
    return { count: 1 };
  }

  replaceMethod(prisma.user, 'findFirst', async ({ where }: any) =>
    users.find((user) => user.email === where.email && user.rollNumber === where.rollNumber) || null);
  replaceMethod(prisma.user, 'findUnique', async ({ where }: any) =>
    users.find((user) => user.id === where.id || user.email === where.email) || null);
  replaceMethod(prisma.user, 'update', async ({ where, data }: any) => {
    const user = users.find((candidate) => candidate.id === where.id)!;
    for (const [key, value] of Object.entries(data)) {
      if (key === 'authVersion' && typeof value === 'object' && value !== null && 'increment' in value) {
        user.authVersion += Number((value as { increment: number }).increment);
      } else {
        Object.assign(user, { [key]: value });
      }
    }
    return user;
  });
  replaceMethod(prisma.passwordResetOtp, 'count', async ({ where }: any) =>
    records.filter((row) => row.studentId === where.studentId && row.createdAt >= where.createdAt.gte).length);
  replaceMethod(prisma.passwordResetOtp, 'findFirst', async ({ where }: any) =>
    records.filter((row) => row.studentId === where.studentId).sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())[0] || null);
  replaceMethod(prisma.passwordResetOtp, 'findUnique', async ({ where }: any) => {
    const row = records.find((candidate) => candidate.requestId === where.requestId);
    return row ? { ...row, student: users.find((user) => user.id === row.studentId)! } : null;
  });
  replaceMethod(prisma.passwordResetOtp, 'create', async ({ data }: any) => {
    const user = users.find((candidate) => candidate.id === data.studentId)!;
    const row = { ...data, id: `reset-${records.length + 1}`, createdAt: new Date(), attempts: 0, usedAt: null, verifiedAt: null, resetTokenHash: null, resetExpiresAt: null, student: user };
    records.push(row);
    return row;
  });
  replaceMethod(prisma.passwordResetOtp, 'update', async ({ where, data }: any) => {
    const row = records.find((candidate) => candidate.id === where.id)!;
    if (data.attempts?.increment) row.attempts += data.attempts.increment;
    else Object.assign(row, data);
    return row;
  });
  replaceMethod(prisma.passwordResetOtp, 'updateMany', async ({ where, data }: any) => {
    if (where.id) return updateOtpMany({ where, data });
    let count = 0;
    for (const row of records.filter((candidate) => candidate.studentId === where.studentId && candidate.usedAt === null)) {
      Object.assign(row, data);
      count++;
    }
    return { count };
  });

  const tx = {
    user: { update: (args: any) => (prisma.user.update as any)(args) },
    passwordResetOtp: { updateMany: (args: any) => (prisma.passwordResetOtp.updateMany as any)(args) },
  };
  replaceMethod(prisma, '$transaction', async (operations: any) =>
    Array.isArray(operations) ? Promise.all(operations) : operations(tx));

  const server = app.listen(0);
  try {
    await new Promise<void>((resolve) => server.once('listening', resolve));
    const address = server.address();
    assert.ok(address && typeof address !== 'string');
    const baseUrl = `http://127.0.0.1:${address.port}`;
    globalThis.fetch = async (input, init) => {
      if (String(input) === process.env.GOOGLE_APPS_SCRIPT_EMAIL_URL) {
        const message = JSON.parse(String(init?.body || '{}')) as { to: string; text: string };
        const otp = message.text.match(/\b\d{6}\b/)?.[0];
        assert.ok(otp);
        providerOtpByEmail.set(message.to, otp);
        return failEmailProvider
          ? new Response('provider response body must not leak', { status: 503 })
          : new Response(JSON.stringify({ ok: true }), { status: 200 });
      }
      return originalFetch(input, init);
    };

    async function post(path: string, body: unknown, headers: Record<string, string> = {}) {
      const response = await originalFetch(`${baseUrl}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(body),
      });
      return { response, body: await response.json() as Record<string, any> };
    }

    const genericMessage = 'If the account exists, a password reset OTP has been requested.';
    const unknownAccount = await post('/api/auth/forgot-password/request', {
      email: 'unknown@example.invalid', rollNumber: 'UNKNOWN-001',
    }, { 'X-Forwarded-For': '192.0.2.10' });
    assert.equal(unknownAccount.response.status, 202);
    assert.equal(unknownAccount.body.message, genericMessage);

    failEmailProvider = true;
    const failedDelivery = await post('/api/auth/forgot-password/request', {
      email: 'delivery-failure@example.invalid', rollNumber: 'TEST-002',
    }, { 'X-Forwarded-For': '192.0.2.11' });
    assert.equal(failedDelivery.response.status, 202);
    assert.equal(failedDelivery.body.message, genericMessage);
    assert.equal(failedDelivery.body.message.includes('delivery-failure'), false);
    failEmailProvider = false;

    const login = await post('/api/auth/student/login', {
      name: 'Test Student',
      rollNumber: 'TEST-001',
      email: 'student@example.invalid',
      password: 'Old-password-123',
    });
    assert.equal(login.response.status, 200);
    const oldSession = login.body.token as string;

    const requested = await post('/api/auth/forgot-password/request', {
      email: 'student@example.invalid',
      rollNumber: 'TEST-001',
    }, { 'X-Forwarded-For': '192.0.2.12' });
    assert.equal(requested.response.status, 202);
    assert.equal(requested.body.message, genericMessage);
    const otp = providerOtpByEmail.get('student@example.invalid');
    assert.ok(otp);

    const wrongOtp = await post('/api/auth/forgot-password/verify-otp', {
      email: 'student@example.invalid',
      rollNumber: 'TEST-001',
      requestId: requested.body.requestId,
      otp: otp === '000000' ? '000001' : '000000',
    });
    assert.equal(wrongOtp.response.status, 400);

    const verified = await post('/api/auth/forgot-password/verify-otp', {
      email: 'student@example.invalid',
      rollNumber: 'TEST-001',
      requestId: requested.body.requestId,
      otp,
    });
    assert.equal(verified.response.status, 200);

    const reset = await post('/api/auth/forgot-password/reset', {
      email: 'student@example.invalid',
      rollNumber: 'TEST-001',
      requestId: requested.body.requestId,
      resetToken: verified.body.resetToken,
      password: 'New-password-123',
      confirmPassword: 'New-password-123',
    });
    assert.equal(reset.response.status, 200);
    assert.notEqual(users[0].passwordHash, 'New-password-123');
    assert.equal(await bcrypt.compare('New-password-123', users[0].passwordHash), true);
    assert.equal(users[0].authVersion, 1);

    const staleSession = await originalFetch(`${baseUrl}/api/auth/logout`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${oldSession}` },
    });
    assert.equal(staleSession.status, 401);
  } finally {
    globalThis.fetch = originalFetch;
    await new Promise<void>((resolve, reject) => server.close((error?: Error) => error ? reject(error) : resolve()));
    for (const restore of restorers.reverse()) restore();
  }
});
