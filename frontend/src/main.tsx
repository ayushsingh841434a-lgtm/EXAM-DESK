import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Activity, BookOpen, CalendarDays, Check, CircleHelp, ClipboardList, Clock3, Eye, EyeOff, FileBarChart2, LayoutDashboard, LogOut, Menu, Search, ShieldAlert, Users, X } from 'lucide-react';
import './style.css';
import './design.css';
import './responsive-overrides.css';
import { getViolationEventKey, isBlockedShortcut } from './antiCheat';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8080';
async function api(path: string, opts: RequestInit = {}) {
  const token = localStorage.getItem('token');
  const r = await fetch(API + path, { ...opts, credentials: 'include', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(opts.headers || {}) } });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || 'Request failed');
  return d;
}

function Login({ onLogin }: { onLogin: (u: any) => void }) {
  const [mode, setMode] = useState<'student' | 'admin' | 'register' | 'forgot'>('student');
  const [form, setForm] = useState({ name: '', rollNumber: '', email: '', password: '', confirmPassword: '', otp: '' });
  const [requestId, setRequestId] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [verificationPath, setVerificationPath] = useState('');
  const [notice, setNotice] = useState(() => new URLSearchParams(window.location.search).has('verified') ? 'Email verified. Sign in to continue.' : '');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [otpCountdown, setOtpCountdown] = useState(0);

  useEffect(() => {
    if (!otpCountdown) return;
    const timer = window.setTimeout(() => setOtpCountdown(value => Math.max(0, value - 1)), 1000);
    return () => window.clearTimeout(timer);
  }, [otpCountdown]);

  function setField(field: keyof typeof form, value: string) { setForm(current => ({ ...current, [field]: value })); }
  function changeMode(next: typeof mode) { setMode(next); setErr(''); setNotice(''); setRequestId(''); setResetToken(''); }
  async function submitLogin(e: React.FormEvent) {
    e.preventDefault(); setErr(''); setNotice(''); setBusy(true);
    try {
      const path = mode === 'admin' ? '/api/auth/login' : '/api/auth/student/login';
      const body = mode === 'admin' ? { email: form.email, password: form.password } : { name: form.name, rollNumber: form.rollNumber, email: form.email, password: form.password };
      const result = await api(path, { method: 'POST', body: JSON.stringify(body) });
      if (result.token) localStorage.setItem('token', result.token);
      else localStorage.removeItem('token');
      onLogin(result.user);
    } catch (error: any) { setErr(error.message); }
    finally { setBusy(false); }
  }
  async function submitRegistration(e: React.FormEvent) {
    e.preventDefault(); setErr(''); setNotice(''); setBusy(true);
    if (form.password !== form.confirmPassword) { setErr('Password and confirmation do not match.'); setBusy(false); return; }
    try {
      const result = await api('/api/auth/register', { method: 'POST', body: JSON.stringify({ name: form.name, rollNumber: form.rollNumber, email: form.email, password: form.password }) });
      setNotice(result.devVerifyPath ? 'Registration complete. Verify your account before signing in.' : result.message);
      setVerificationPath(result.devVerifyPath || '');
      setMode('student'); setForm(current => ({ ...current, password: '', confirmPassword: '' }));
    } catch (error: any) { setErr(error.message); }
    finally { setBusy(false); }
  }
  async function verifyRegistration() {
    if (!verificationPath) return;
    setErr(''); setBusy(true);
    try {
      await api(verificationPath);
      setVerificationPath('');
      setNotice('Account verified. Sign in with the same name, roll number, email, and password you registered with.');
    } catch (error: any) { setErr(error.message); }
    finally { setBusy(false); }
  }
  async function requestOtp(e: React.FormEvent) {
    e.preventDefault(); setErr(''); setNotice(''); setBusy(true);
    try {
      const result = await api('/api/auth/forgot-password/request', { method: 'POST', body: JSON.stringify({ email: form.email, rollNumber: form.rollNumber }) });
      setRequestId(result.requestId);
      setOtpCountdown(60);
      setNotice(result.message);
    } catch (error: any) { setErr(error.message); }
    finally { setBusy(false); }
  }
  async function verifyOtp(e: React.FormEvent) {
    e.preventDefault(); setErr(''); setNotice(''); setBusy(true);
    try {
      const result = await api('/api/auth/forgot-password/verify-otp', { method: 'POST', body: JSON.stringify({ email: form.email, rollNumber: form.rollNumber, requestId, otp: form.otp }) });
      setResetToken(result.resetToken);
      setNotice('OTP verified. Choose a new password.');
    } catch (error: any) { setErr(error.message); }
    finally { setBusy(false); }
  }
  async function resetPassword(e: React.FormEvent) {
    e.preventDefault(); setErr(''); setNotice('');
    if (form.password !== form.confirmPassword) { setErr('New password and confirmation do not match.'); return; }
    setBusy(true);
    try {
      const result = await api('/api/auth/forgot-password/reset', { method: 'POST', body: JSON.stringify({ email: form.email, rollNumber: form.rollNumber, requestId, resetToken, password: form.password, confirmPassword: form.confirmPassword }) });
      setNotice(result.message); setForm(current => ({ ...current, password: '', confirmPassword: '', otp: '' })); setMode('student'); setRequestId(''); setResetToken('');
    } catch (error: any) { setErr(error.message); }
    finally { setBusy(false); }
  }

  const passwordInput = (field: 'password' | 'confirmPassword', label: string, autoComplete: string, minLength = 1) => <label>{label}<span className="passwordControl"><input autoComplete={autoComplete} type={showPassword ? 'text' : 'password'} minLength={minLength} required value={form[field]} onChange={e => setField(field, e.target.value)} /><button type="button" className="passwordToggle" aria-label={showPassword ? 'Hide password' : 'Show password'} onClick={() => setShowPassword(value => !value)}>{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button></span></label>;
  const passwordFields = <>{passwordInput('password', 'Password', mode === 'register' ? 'new-password' : 'current-password', mode === 'register' ? 8 : 1)}{mode === 'register' && passwordInput('confirmPassword', 'Confirm password', 'new-password', 8)}</>;
  return <main className="center"><section className="card auth">
    <h1>{mode === 'forgot' ? 'Reset Password' : mode === 'register' ? 'Student Registration' : mode === 'admin' ? 'Admin Login' : 'Student Login'}</h1>
    <p className="muted">Secure examination platform</p>
    {mode !== 'forgot' && mode !== 'register' && <div className="tabs authModes"><button type="button" className={mode === 'student' ? 'activeTab' : 'secondary'} onClick={() => changeMode('student')}>Student</button><button type="button" className={mode === 'admin' ? 'activeTab' : 'secondary'} onClick={() => changeMode('admin')}>Admin</button></div>}
    {mode === 'student' && <form onSubmit={submitLogin}>
      <label>Full Name<input autoComplete="name" required value={form.name} onChange={e => setField('name', e.target.value)} /></label>
      <label>Roll Number<input autoComplete="username" required value={form.rollNumber} onChange={e => setField('rollNumber', e.target.value)} /></label>
      <label>Email Address<input autoComplete="email" type="email" required value={form.email} onChange={e => setField('email', e.target.value)} /></label>
      {passwordInput('password', 'Password', 'current-password')}
      {err && <p className="err" role="alert">{err}</p>}{notice && <p className="notice" role="status">{notice}</p>}{verificationPath && <button type="button" className="secondary" disabled={busy} onClick={verifyRegistration}>{busy ? 'Verifying…' : 'Verify account (local testing)'}</button>}
      <button disabled={busy}>{busy ? 'Signing in…' : 'Login'}</button>
      <button type="button" className="link" onClick={() => changeMode('forgot')}>Forgot Password?</button>
      <button type="button" className="link" onClick={() => changeMode('register')}>New student? Register</button>
    </form>}
    {mode === 'admin' && <form onSubmit={submitLogin}>
      <label>Email Address<input autoComplete="username" type="email" required value={form.email} onChange={e => setField('email', e.target.value)} /></label>
      {passwordInput('password', 'Password', 'current-password')}
      {err && <p className="err" role="alert">{err}</p>}{notice && <p className="notice" role="status">{notice}</p>}
      <button disabled={busy}>{busy ? 'Signing in…' : 'Login'}</button>
      <button type="button" className="link" onClick={() => changeMode('student')}>Student login</button>
    </form>}
    {mode === 'register' && <form onSubmit={submitRegistration}>
      <label>Full Name<input autoComplete="name" required value={form.name} onChange={e => setField('name', e.target.value)} /></label>
      <label>Roll Number<input autoComplete="username" required value={form.rollNumber} onChange={e => setField('rollNumber', e.target.value)} /></label>
      <label>Email Address<input autoComplete="email" type="email" required value={form.email} onChange={e => setField('email', e.target.value)} /></label>
      {passwordFields}{err && <p className="err" role="alert">{err}</p>}{notice && <p className="notice" role="status">{notice}</p>}
      <button disabled={busy}>{busy ? 'Creating…' : 'Create account'}</button>
      <button type="button" className="link" onClick={() => changeMode('student')}>Already registered? Login</button>
    </form>}
    {mode === 'forgot' && <>
      {!requestId && <form onSubmit={requestOtp}>
        <label>Registered Email<input autoComplete="email" type="email" required value={form.email} onChange={e => setField('email', e.target.value)} /></label>
        <label>Roll Number<input autoComplete="username" required value={form.rollNumber} onChange={e => setField('rollNumber', e.target.value)} /></label>
        {err && <p className="err" role="alert">{err}</p>}{notice && <p className="notice" role="status">{notice}</p>}
        <button disabled={busy}>{busy ? 'Sending…' : 'Send OTP'}</button>
      </form>}
      {requestId && !resetToken && <form onSubmit={verifyOtp}>
        <p className="notice" role="status">{notice || 'If the account exists, a password reset OTP has been requested.'}</p>
        <label>OTP<input inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required value={form.otp} onChange={e => setField('otp', e.target.value)} /></label>
        {err && <p className="err" role="alert">{err}</p>}
        <button disabled={busy}>{busy ? 'Verifying…' : 'Verify OTP'}</button>
        <div className="otpResend"><span>{otpCountdown ? `Resend available in 00:${String(otpCountdown).padStart(2, '0')}` : 'Didn’t receive the code?'}</span><button type="button" className="link" disabled={busy || otpCountdown > 0} onClick={requestOtp as any}>Resend OTP</button></div>
      </form>}
      {resetToken && <form onSubmit={resetPassword}>
        {passwordInput('password', 'New Password', 'new-password', 8)}
        {passwordInput('confirmPassword', 'Confirm New Password', 'new-password', 8)}
        {err && <p className="err" role="alert">{err}</p>}{notice && <p className="notice" role="status">{notice}</p>}
        <button disabled={busy}>{busy ? 'Resetting…' : 'Reset Password'}</button>
      </form>}
      <button type="button" className="link" onClick={() => changeMode('student')}>Back to login</button>
    </>}
  </section></main>;
}

function Security({ attemptId, sessionToken, onViolation }: { attemptId: string; sessionToken?: string; onViolation: (n: number, cancelled: boolean, terminated?: boolean, reason?: string) => void }) {
  useEffect(() => {
    const seen = new Set<string>();
    const send = (type: string, detail: string) => {
      const key = getViolationEventKey(type);
      if (seen.has(key)) return;
      seen.add(key);
      api(`/api/attempts/${attemptId}/violations`, {
        method: 'POST',
        body: JSON.stringify({ type, metadata: detail ? { detail } : undefined, sessionToken })
      }).then((x) => onViolation(x.violationCount, x.cancelled, x.terminated, x.reason)).catch(() => {});
    };
    const protectedEvent = (event: Event, type: string, detail: string) => {
      if (!(event.target instanceof Element) || !event.target.closest('[data-exam-protected="true"]')) return;
      event.preventDefault();
      send(type, detail);
    };
    const contextMenu = (event: Event) => protectedEvent(event, 'CONTEXT_MENU_ATTEMPT', 'contextmenu');
    const copy = (event: Event) => protectedEvent(event, 'COPY_ATTEMPT', 'copy');
    const cut = (event: Event) => protectedEvent(event, 'COPY_ATTEMPT', 'cut');
    const paste = (event: Event) => protectedEvent(event, 'PASTE_ATTEMPT', 'paste');
    const dragStart = (event: Event) => protectedEvent(event, 'COPY_ATTEMPT', 'dragstart');
    const drop = (event: Event) => protectedEvent(event, 'PASTE_ATTEMPT', 'drop');
    const selectStart = (event: Event) => {
      if (event.target instanceof Element && event.target.closest('input:not([type="radio"]):not([type="checkbox"]),textarea,[contenteditable="true"]')) return;
      protectedEvent(event, 'COPY_ATTEMPT', 'selectstart');
    };
    const vis = () => { if (document.hidden) send('TAB_SWITCH', 'visibilitychange'); };
    const blur = () => send('WINDOW_BLUR', 'window.blur');
    const fs = () => { if (!document.fullscreenElement) send('FULLSCREEN_EXIT', 'fullscreenchange'); };
    const key = (e: KeyboardEvent) => {
      const keyName = e.key.toLowerCase();
      if ((e.ctrlKey || e.metaKey) && isBlockedShortcut(e) && document.querySelector('[data-exam-protected="true"]')) {
        e.preventDefault();
        const type = keyName === 'v' ? 'PASTE_ATTEMPT' : 'COPY_ATTEMPT';
        send(type, keyName);
      }
    };
    document.addEventListener('visibilitychange', vis);
    window.addEventListener('blur', blur);
    document.addEventListener('fullscreenchange', fs);
    document.addEventListener('keydown', key, true);
    document.addEventListener('contextmenu', contextMenu, true);
    document.addEventListener('copy', copy, true);
    document.addEventListener('cut', cut, true);
    document.addEventListener('paste', paste, true);
    document.addEventListener('dragstart', dragStart, true);
    document.addEventListener('drop', drop, true);
    document.addEventListener('selectstart', selectStart, true);
    return () => {
      document.removeEventListener('visibilitychange', vis);
      window.removeEventListener('blur', blur);
      document.removeEventListener('fullscreenchange', fs);
      document.removeEventListener('keydown', key, true);
      document.removeEventListener('contextmenu', contextMenu, true);
      document.removeEventListener('copy', copy, true);
      document.removeEventListener('cut', cut, true);
      document.removeEventListener('paste', paste, true);
      document.removeEventListener('dragstart', dragStart, true);
      document.removeEventListener('drop', drop, true);
      document.removeEventListener('selectstart', selectStart, true);
    };
  }, [attemptId, sessionToken]);
  return null;
}

function Student({ user }: { user: any }) {
  const [tests, setTests] = useState<any[]>([]); const [attempt, setAttempt] = useState<any>(); const [i, setI] = useState(0); const [ans, setAns] = useState<Record<string, string>>({}); const [marked, setMarked] = useState<Set<number>>(new Set()); const [viol, setViol] = useState(0); const [msg, setMsg] = useState('');
  async function load() { setTests(await api('/api/tests')); } useEffect(() => { load(); }, []);
  useEffect(() => { if (!attempt) return; const t = setInterval(async () => { try { const a = await api('/api/attempts/' + attempt.id); if (a.terminated || a.status === 'TERMINATED_CHEATING') { setMsg('Exam terminated due to anti-cheating policy.'); setAttempt(null); return; } if (a.status !== 'IN_PROGRESS') { setMsg(`Exam ended. Score: ${a.score ?? 0}`); setAttempt(null); return; } setAttempt({ ...a, sessionToken: attempt.sessionToken }); } catch {} }, 2000); return () => clearInterval(t); }, [attempt?.id]);
  async function start(id: string) {
    const a = await api('/api/attempts/start', { method: 'POST', body: JSON.stringify({ testId: id }) });
    const full = await api('/api/attempts/' + a.id);
    const sessionToken = a.sessionToken || full.sessionToken || '';
    setAttempt({ ...full, sessionToken });
    setI(0);
    setMarked(new Set());
    setViol(full.violationCount || 0);
    const initial: Record<string, string> = {};
    full.answers.forEach((x: any) => x.selectedOptionId && (initial[x.questionId] = x.selectedOptionId));
    setAns(initial);
    await document.documentElement.requestFullscreen?.().catch(() => {});
  }
  async function save(q: string, o: string | null) { if (!attempt) return; setAns({ ...ans, [q]: o || '' }); await api(`/api/attempts/${attempt.id}/answers`, { method: 'PUT', body: JSON.stringify({ questionId: q, selectedOptionId: o }) }); }
  async function submit() { if (!attempt) return; const a = await api('/api/attempts/' + attempt.id + '/submit', { method: 'POST' }); setMsg(`Submitted. Score: ${a.score ?? 0}`); setAttempt(null); load(); }
  function formatTime(seconds: number) { const safe = Math.max(0, seconds); return `${String(Math.floor(safe / 3600)).padStart(2, '0')}:${String(Math.floor((safe % 3600) / 60)).padStart(2, '0')}:${String(safe % 60).padStart(2, '0')}`; }
  if (!attempt) return <main className="wrap studentHome">
    <Top title="Student Portal" />
    <section className="studentWelcome"><h1>Welcome back, {user.name}</h1><p>Your next step starts with a focused attempt. Your exams and progress are ready below.</p></section>
    {msg && <div className="notice"><Check size={17} /> {msg}</div>}
    <div className="stats studentStats"><Stat label="Available tests" value={tests.length} icon={<ClipboardList size={18} />} tone="violet" /><Stat label="Questions ready" value={tests.reduce((sum, test) => sum + (test._count?.questions || 0), 0)} icon={<BookOpen size={18} />} tone="green" /><Stat label="Exam minutes" value={tests.reduce((sum, test) => sum + (test.duration || 0), 0)} icon={<Clock3 size={18} />} tone="amber" /><Stat label="Your roll number" value={user.rollNumber || '—'} icon={<Users size={18} />} tone="blue" /></div>
    <div className="sectionHead studentSectionTitle"><div><h2>Available exams</h2><p className="muted">Choose an open exam when you are ready to begin.</p></div><span className="statusBadge live">{tests.length} available</span></div>
    {tests.length === 0 && <div className="card emptyState"><ClipboardList size={24} /><h3>No exams available</h3><p className="muted">There are no live tests in your exam window right now.</p></div>}
    <div className="examList">{tests.map(t => <article className="card row testCard" key={t.id}><div className="testCardBody"><div className="testCardHead"><div><span className="statusBadge live">Available</span><h3>{t.title}</h3></div><span className="testIcon"><BookOpen size={20} /></span></div><p>{t.description || 'Online examination'}</p><div className="testFacts"><span className="testFact"><ClipboardList size={15} />{t._count?.questions || 0} questions</span><span className="testFact"><Clock3 size={15} />{t.duration} minutes</span><span className="testFact"><Users size={15} />Up to {t.maxAttempts} attempts</span><span className="testFact"><CalendarDays size={15} />Starts {new Date(t.startTime).toLocaleString()}</span><span className="testFact"><CalendarDays size={15} />Ends {new Date(t.endTime).toLocaleDateString()}</span></div></div><button onClick={() => start(t.id)}>Start test</button></article>)}</div>
  </main>;
  const q = attempt.questions[i];
  const answeredCount = attempt.questions.filter((question: any) => Boolean(ans[question.id])).length;
  return <main className="exam">
    <Security attemptId={attempt.id} sessionToken={attempt.sessionToken} onViolation={(n, cancelled, terminated, reason) => { setViol(n); if (terminated || cancelled) { setMsg(reason ? `Exam terminated due to ${reason}.` : 'Exam terminated due to anti-cheating policy.'); setAttempt(null); } }} />
    <header className="examTopbar"><div className="examTitle"><span className="examBrandIcon"><BookOpen size={18} /></span><div><b>{attempt.test.title}</b><small>{user.name}</small></div></div><div className="examTopProgress"><span>Question {i + 1} of {attempt.questions.length}</span><div className="progressBar"><span style={{ width: `${((i + 1) / attempt.questions.length) * 100}%` }} /></div></div><div className={`timerChip ${attempt.remainingSeconds <= 300 ? 'low' : ''}`}><Clock3 size={16} /><span>{formatTime(attempt.remainingSeconds)}</span></div><span className="violationChip"><ShieldAlert size={15} />{viol}/{attempt.test.violationLimit}</span><button className="examSubmit" onClick={submit}>Submit exam</button></header>
    <div className="examLayout">
      <section className="examMain">
        <section className="card examCard examProtected" data-exam-protected="true">
          <p className="examSecurityWarning">Copying, pasting, text selection, screenshots, and switching away from the exam are restricted during the test.</p>
          <p className="examSecurityLimit">Browser controls cannot prevent screenshots, screen recording, or photos taken with another device.</p>
          <div className="questionHeader"><div><div className="progress">Question {i + 1} <span className="muted">of {attempt.questions.length}</span></div><h2>{q.questionText}</h2></div><span className="questionMark">{q.marks} mark{q.marks === 1 ? '' : 's'}</span></div>
          <div className="answerList">{q.options.map((o: any, optionIndex: number) => <label className="option" key={o.id}><input type="radio" name={q.id} checked={ans[q.id] === o.id} onChange={() => save(q.id, o.id)} /><span className="optionLetter">{String.fromCharCode(65 + optionIndex)}</span><span>{o.optionText}</span></label>)}</div>
          <div className="examQuestionActions"><button className="secondary" disabled={i === 0} onClick={() => setI(i - 1)}>Previous</button><button type="button" className={marked.has(i) ? 'reviewButton marked' : 'reviewButton'} onClick={() => setMarked(current => { const next = new Set(current); if (next.has(i)) next.delete(i); else next.add(i); return next; })}>{marked.has(i) ? 'Remove review mark' : 'Mark for review'}</button>{i < attempt.questions.length - 1 ? <button onClick={() => setI(i + 1)}>Next question</button> : <button onClick={submit}>Submit exam</button>}</div>
        </section>
      </section>
      <aside className="card examSidebar"><div className="paletteHeading"><div><h3>Question palette</h3><small>{answeredCount} of {attempt.questions.length} answered</small></div><CircleHelp size={18} /></div><div className="questionPalette">{attempt.questions.map((question: any, index: number) => <button key={question.id} type="button" aria-label={`Question ${index + 1}${ans[question.id] ? ', answered' : ', not answered'}${marked.has(index) ? ', marked for review' : ''}`} className={`${i === index ? 'current' : ''} ${ans[question.id] ? 'answered' : ''} ${marked.has(index) ? 'marked' : ''}`} onClick={() => setI(index)}>{index + 1}</button>)}</div><div className="examNavLegend"><span><i className="legendDot current" />Current</span><span><i className="legendDot" />Answered</span><span><i className="legendDot emptyDot" />Not answered</span><span><i className="legendDot marked" />Marked for review</span></div><div className="paletteFooter"><span><ShieldAlert size={14} />{viol} security events</span><span><Activity size={14} />Session monitored</span></div></aside>
    </div>
  </main>;
}

function Top({ title }: { title: string }) { return <header className="top"><b>{title}</b><button className="secondary" onClick={() => { api('/api/auth/logout', { method: 'POST' }).finally(() => { localStorage.clear(); location.reload(); }); }}>Logout</button></header>; }

function TestEditor({ initial, onSave, onCancel }: { initial?: any; onSave: (v: any) => void; onCancel: () => void }) {
  const [f, setF] = useState({ title: initial?.title || '', description: initial?.description || '', duration: initial?.duration || 30, startTime: initial ? new Date(initial.startTime).toISOString().slice(0, 16) : new Date().toISOString().slice(0, 16), endTime: initial ? new Date(initial.endTime).toISOString().slice(0, 16) : new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 16), violationLimit: initial?.violationLimit || 3, maxAttempts: initial?.maxAttempts || 1 });
  return <div className="modal"><form className="card modalCard" onSubmit={e => { e.preventDefault(); onSave({ ...f, duration: Number(f.duration), violationLimit: Number(f.violationLimit), maxAttempts: Number(f.maxAttempts), startTime: new Date(f.startTime).toISOString(), endTime: new Date(f.endTime).toISOString() }); }}><h2>{initial ? 'Edit Test' : 'Create Test'}</h2><input placeholder="Test title" value={f.title} onChange={e => setF({ ...f, title: e.target.value })} required /><textarea placeholder="Description" value={f.description} onChange={e => setF({ ...f, description: e.target.value })} /><div className="formGrid"><label>Duration (minutes)<input type="number" value={f.duration} onChange={e => setF({ ...f, duration: Number(e.target.value) })} /></label><label>Max attempts<input type="number" value={f.maxAttempts} onChange={e => setF({ ...f, maxAttempts: Number(e.target.value) })} /></label><label>Violation limit<input type="number" value={f.violationLimit} onChange={e => setF({ ...f, violationLimit: Number(e.target.value) })} /></label><label>Start<input type="datetime-local" value={f.startTime} onChange={e => setF({ ...f, startTime: e.target.value })} /></label><label>End<input type="datetime-local" value={f.endTime} onChange={e => setF({ ...f, endTime: e.target.value })} /></label></div><div className="actions"><button type="button" className="secondary" onClick={onCancel}>Cancel</button><button>Save Test</button></div></form></div>;
}

function QuestionEditor({ initial, onSave, onCancel }: { initial?: any; onSave: (v: any) => void; onCancel: () => void }) {
  const [q, setQ] = useState(initial || { questionText: '', marks: 1, negativeMarks: 0, explanation: '', options: ['', '', '', ''].map(optionText => ({ optionText, isCorrect: false })) });
  const updateOpt = (i: number, patch: any) => setQ({ ...q, options: q.options.map((x: any, j: number) => j === i ? { ...x, ...patch } : x) });
  return <div className="modal"><form className="card modalCard" onSubmit={e => { e.preventDefault(); onSave({ ...q, marks: Number(q.marks), negativeMarks: Number(q.negativeMarks) }); }}><h2>{initial ? 'Edit Question' : 'Add Question'}</h2><textarea className="questionInput" placeholder="Question text" value={q.questionText} onChange={e => setQ({ ...q, questionText: e.target.value })} required />{q.options.map((o: any, i: number) => <div className="optionEdit" key={i}><input placeholder={`Option ${String.fromCharCode(65 + i)}`} value={o.optionText} onChange={e => updateOpt(i, { optionText: e.target.value })} required /><label><input type="radio" name="correct" checked={o.isCorrect} onChange={() => setQ({ ...q, options: q.options.map((x: any, j: number) => ({ ...x, isCorrect: j === i })) })} /> Correct</label></div>)}<div className="formGrid"><label>Marks<input type="number" step="0.25" value={q.marks} onChange={e => setQ({ ...q, marks: Number(e.target.value) })} /></label><label>Negative marks<input type="number" step="0.25" value={q.negativeMarks} onChange={e => setQ({ ...q, negativeMarks: Number(e.target.value) })} /></label></div><textarea placeholder="Explanation (optional)" value={q.explanation || ''} onChange={e => setQ({ ...q, explanation: e.target.value })} /><div className="actions"><button type="button" className="secondary" onClick={onCancel}>Cancel</button><button>Save Question</button></div></form></div>;
}

function Admin({ user }: { user: any }) {
  const [tab, setTab] = useState<'dashboard' | 'tests' | 'questions' | 'monitor' | 'results' | 'students'>('dashboard'); const [tests, setTests] = useState<any[]>([]); const [stats, setStats] = useState<any>({}); const [monitor, setMonitor] = useState<any[]>([]); const [results, setResults] = useState<any[]>([]); const [students, setStudents] = useState<any[]>([]); const [selectedTest, setSelectedTest] = useState<any>(null); const [questions, setQuestions] = useState<any[]>([]); const [detail, setDetail] = useState<any>(null); const [modal, setModal] = useState<any>(null); const [error, setError] = useState(''); const [menuOpen, setMenuOpen] = useState(false); const [searchQuery, setSearchQuery] = useState(''); const [searchOpen, setSearchOpen] = useState(false);
  async function load() { try { setTests(await api('/api/tests')); setStats(await api('/api/admin/stats')); setMonitor(await api('/api/admin/monitor')); setResults(await api('/api/admin/results')); setStudents(await api('/api/admin/students')); } catch (e: any) { setError(e.message); } }
  async function loadQuestions(testId: string) { setQuestions(await api(`/api/admin/tests/${testId}/questions`)); }
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, []);
  async function status(id: string, s: string) { await api(`/api/tests/${id}/status`, { method: 'PATCH', body: JSON.stringify({ status: s }) }); await load(); }
  async function saveTest(v: any) { if (modal.initial) await api(`/api/tests/${modal.initial.id}`, { method: 'PATCH', body: JSON.stringify(v) }); else await api('/api/tests', { method: 'POST', body: JSON.stringify(v) }); setModal(null); await load(); }
  async function deleteTest(t: any) { if (!confirm(`Delete test "${t.title}"?`)) return; try { await api(`/api/tests/${t.id}`, { method: 'DELETE' }); await load(); } catch (e: any) { alert(e.message); } }
  async function saveQuestion(v: any) { try { if (modal.initial) await api(`/api/questions/${modal.initial.id}`, { method: 'PATCH', body: JSON.stringify(v) }); else await api(`/api/tests/${selectedTest.id}/questions`, { method: 'POST', body: JSON.stringify(v) }); setModal(null); await loadQuestions(selectedTest.id); await load(); } catch (e: any) { alert(e.message); } }
  async function deleteQuestion(q: any) { if (!confirm('Delete this question?')) return; try { await api(`/api/questions/${q.id}`, { method: 'DELETE' }); await loadQuestions(selectedTest.id); } catch (e: any) { alert(e.message); } }
  async function showResult(id: string) { setDetail(await api(`/api/admin/results/${id}`)); }
  const totals = useMemo(() => ({ questions: tests.reduce((n, t) => n + (t._count?.questions || 0), 0) }), [tests]);
  const averageScore = results.length ? Math.round(results.reduce((sum, row) => sum + (row.score || 0), 0) / results.length) : 0;
  const filteredTests = tests.filter(test => `${test.title} ${test.description || ''} ${test.status}`.toLowerCase().includes(searchQuery.toLowerCase()));
  const filteredStudents = students.filter(student => `${student.name} ${student.rollNumber || ''} ${student.email}`.toLowerCase().includes(searchQuery.toLowerCase()));
  const navigation = [
    { key: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard /> },
    { key: 'students', label: 'Students', icon: <Users /> },
    { key: 'tests', label: 'Tests', icon: <ClipboardList /> },
    { key: 'questions', label: 'Questions', icon: <CircleHelp /> },
    { key: 'monitor', label: 'Live monitoring', icon: <Activity /> },
    { key: 'results', label: 'Results & reports', icon: <FileBarChart2 /> },
  ];
  const changeTab = (next: string) => { setTab(next as typeof tab); setMenuOpen(false); };
  return <div className={`adminShell ${menuOpen ? 'menuOpen' : ''}`}>
    <button className="mobileShade" aria-label="Close navigation" onClick={() => setMenuOpen(false)} />
    <aside className="adminSidebar"><div className="brand"><span className="brandMark"><BookOpen size={19} /></span><span className="brandText"><strong>Exam Office</strong><small>INSTITUTE PORTAL</small></span></div><span className="sideLabel">Workspace</span><nav className="sideNav">{navigation.map(item => <button key={item.key} className={tab === item.key ? 'active' : ''} onClick={() => changeTab(item.key)}>{item.icon}<span>{item.label}</span></button>)}</nav><div className="sideFoot"><span className="sideLabel">Signed in</span><button onClick={() => { api('/api/auth/logout', { method: 'POST' }).finally(() => { localStorage.clear(); location.reload(); }); }}><LogOut size={17} />Log out</button></div></aside>
    <div className="adminWorkspace"><header className="adminTopbar"><div className="adminTopLeft"><button className="menuToggle" aria-label="Open navigation" onClick={() => setMenuOpen(true)}><Menu size={18} /></button><div><h1>{tab === 'dashboard' ? 'Overview' : navigation.find(item => item.key === tab)?.label}</h1><span className="adminDate">{new Date().toLocaleDateString(undefined, { weekday: 'long', month: 'long', day: 'numeric' })}</span></div></div><div className="adminTopActions"><label className={`adminSearch ${searchOpen ? 'open' : ''}`}><button type="button" aria-label={searchOpen ? 'Close search' : 'Open search'} onClick={() => setSearchOpen(value => !value)}>{searchOpen ? <X size={16} /> : <Search size={16} />}</button><input aria-label="Search this view" placeholder="Search students or tests" value={searchQuery} onChange={event => setSearchQuery(event.target.value)} /></label><button className="iconAction" aria-label="Open live monitoring" title="Live monitoring" onClick={() => changeTab('monitor')}><Activity size={17} /></button><div className="adminProfile"><span className="avatar">{String(user.name || 'A').slice(0, 1).toUpperCase()}</span><div><b>{user.name}</b><small>Administrator</small></div></div></div></header><main className="admin adminContent">{error && <div className="errBox">{error}</div>}
    {tab === 'dashboard' && <><div className="adminHeading"><div><h2>Good day, {user.name}</h2><p>Here is the latest activity across your examination platform.</p></div><button onClick={() => setModal({ type: 'test' })}>＋ Create test</button></div><div className="stats"><Stat label="Total students" value={stats.students ?? 0} icon={<Users size={18} />} tone="violet" meta="Registered accounts" /><Stat label="Total tests" value={stats.tests ?? 0} icon={<ClipboardList size={18} />} tone="blue" meta={`${tests.filter(test => test.status === 'LIVE').length} currently live`} /><Stat label="Questions" value={totals.questions} icon={<BookOpen size={18} />} tone="green" meta="Across all tests" /><Stat label="Active students" value={stats.active ?? 0} icon={<Activity size={18} />} tone="amber" meta="Taking an exam now" /><Stat label="Completed attempts" value={stats.completed ?? 0} icon={<Check size={18} />} tone="green" meta="Submitted or finalized" /><Stat label="Average score" value={averageScore} icon={<FileBarChart2 size={18} />} tone="violet" meta="From available results" /></div><div className="grid2 dashboardColumns"><div className="card quickActions"><div className="panelHeading"><div><h3>Quick actions</h3><p className="muted">Common workspace tasks</p></div><span className="panelIcon"><LayoutDashboard size={17} /></span></div><button onClick={() => setModal({ type: 'test' })}>Create a test</button><button className="secondary" onClick={() => changeTab('questions')}>Manage questions</button><button className="secondary" onClick={() => changeTab('results')}>Review results</button></div><div className="card livePanel"><div className="panelHeading"><div><h3>Live now</h3><p className="muted">Active exam sessions</p></div><span className="liveDot"><Activity size={13} /> Live</span></div>{monitor.length ? monitor.slice(0, 6).map(a => <div className="liveRow" key={a.id}><span className="liveAvatar">{a.user.name.slice(0, 1).toUpperCase()}</span><div className="liveStudent"><b>{a.user.name}</b><small>{a.test.title}</small></div><span className="liveTime"><Clock3 size={13} />{Math.floor(a.remainingSeconds / 60)}m left</span></div>) : <p className="muted">No students are currently taking a test.</p>}<button className="link panelLink" onClick={() => changeTab('monitor')}>Open monitoring →</button></div></div></>}
    {tab === 'tests' && <><div className="adminHeading"><div><h2>Test management</h2><p>Create, schedule, and monitor institute exams.</p></div><button onClick={() => setModal({ type: 'test' })}>＋ Create test</button></div>{filteredTests.map(t => <article className="card row testCard" key={t.id}><div className="testCardBody"><div className="testCardHead"><div><h3>{t.title}</h3><p>{t.description || 'Online examination'}</p></div><span className={`statusBadge ${String(t.status).toLowerCase()}`}>{t.status}</span></div><div className="testFacts"><span className="testFact"><BookOpen size={15} />{t._count?.questions || 0} questions</span><span className="testFact"><Clock3 size={15} />{t.duration} minutes</span><span className="testFact"><Users size={15} />{t._count?.attempts || 0} participants</span><span className="testFact"><CalendarDays size={15} />Created {new Date(t.createdAt).toLocaleDateString()}</span><span className="testFact"><CalendarDays size={15} />Ends {new Date(t.endTime).toLocaleDateString()}</span></div></div><div className="buttonGroup"><button onClick={() => { setSelectedTest(t); changeTab('questions'); loadQuestions(t.id); }}><CircleHelp size={14} /> Questions</button><button className="secondary" onClick={() => setModal({ type: 'test', initial: t })}>Edit</button>{t.status !== 'LIVE' && t.status !== 'ENDED' && <button onClick={() => status(t.id, 'LIVE')}>Allow</button>}{t.status === 'LIVE' && <button className="warning" onClick={() => status(t.id, 'PAUSED')}>Pause</button>}{t.status === 'PAUSED' && <button onClick={() => status(t.id, 'LIVE')}>Resume</button>}{t.status !== 'ENDED' && <button className="danger" onClick={() => status(t.id, 'ENDED')}>End</button>}<button className="danger" onClick={() => deleteTest(t)}>Delete</button></div></article>)}{!filteredTests.length && <div className="card emptyState"><Search size={22} /><h3>No matching tests</h3><p className="muted">Try a different search.</p></div>}</>}
    {tab === 'questions' && <><div className="sectionHead"><div><h2>Question Management</h2><p className="muted">{selectedTest ? `Editing: ${selectedTest.title}` : 'Select a test first'}</p></div>{selectedTest && <button onClick={() => setModal({ type: 'question' })}>+ Add Question</button>}</div><div className="testPicker">{tests.map(t => <button key={t.id} className={selectedTest?.id === t.id ? 'activeTab' : 'secondary'} onClick={() => { setSelectedTest(t); loadQuestions(t.id); }}>{t.title} ({t._count?.questions || 0})</button>)}</div>{selectedTest ? questions.map((q, idx) => <div className="card questionRow" key={q.id}><div><b>Q{idx + 1}. {q.questionText}</b><p>{q.options.map((o: any) => <span key={o.id} className={o.isCorrect ? 'correct' : ''}>{o.optionText}{o.isCorrect ? ' ✓' : ''} · </span>)}</p><small>{q.marks} marks · negative {q.negativeMarks}</small></div><div className="buttonGroup"><button className="secondary" onClick={() => setModal({ type: 'question', initial: q })}>Edit</button><button className="danger" onClick={() => deleteQuestion(q)}>Delete</button></div></div>) : <div className="card">Choose a test above to manage its questions.</div>}</>}
    {tab === 'monitor' && <><div className="sectionHead"><h2>Live Monitoring</h2><span className="liveDot">● Auto-refreshing</span></div><div className="tableWrap"><table><thead><tr><th>Student</th><th>Test</th><th>Time left</th><th>Violations</th><th>Status</th></tr></thead><tbody>{monitor.map(a => <tr key={a.id}><td>{a.user.name}<br /><small>{a.user.email}</small></td><td>{a.test.title}</td><td>{Math.floor(a.remainingSeconds / 60)}m {a.remainingSeconds % 60}s</td><td>{a.violationCount}/{a.test.violationLimit}</td><td>IN PROGRESS</td></tr>)}</tbody></table>{!monitor.length && <p className="empty">No active attempts.</p>}</div></>}
    {tab === 'results' && <><div className="sectionHead"><div><h2>Results</h2><p className="muted">Finalized attempts and security outcomes.</p></div><select aria-label="Filter results by test" value={selectedTest?.id || ''} onChange={async e => { const t = tests.find(x => x.id === e.target.value); setSelectedTest(t || null); setResults(await api(`/api/admin/results${e.target.value ? `?testId=${e.target.value}` : ''}`)); }}><option value="">All tests</option>{tests.map(t => <option key={t.id} value={t.id}>{t.title}</option>)}</select></div><div className="tableWrap"><table><thead><tr><th>Student / Roll Number</th><th>Test</th><th>Score</th><th>Correct</th><th>Wrong</th><th>Skipped</th><th>Violations</th><th>Status</th><th>Action</th></tr></thead><tbody>{results.filter(r => `${r.student.name} ${r.student.email} ${students.find(s => s.email === r.student.email)?.rollNumber || ''} ${r.test.title}`.toLowerCase().includes(searchQuery.toLowerCase())).map(r => <tr key={r.id}><td><b>{r.student.name}</b><br /><small>{students.find(s => s.email === r.student.email)?.rollNumber || 'Roll not set'} · {r.student.email}</small></td><td>{r.test.title}</td><td><b>{r.score ?? 0}</b></td><td>{r.correct}</td><td>{r.wrong}</td><td>{r.skipped}</td><td>{r.violationCount}</td><td><span className={`statusBadge ${String(r.status).toLowerCase()}`}>{String(r.status).replaceAll('_', ' ')}</span></td><td><button onClick={() => showResult(r.id)}>Details</button></td></tr>)}</tbody></table>{!results.length && <p className="empty">No completed results yet.</p>}</div></>}
    {tab === 'students' && <><div className="adminHeading"><div><h2>Student directory</h2><p>Account identity, status, and sign-in activity.</p></div><span className="statusBadge live">{filteredStudents.length} accounts</span></div><div className="tableWrap"><table><thead><tr><th>Student</th><th>Roll Number</th><th>Email</th><th>Status</th><th>Registered</th><th>Last login</th></tr></thead><tbody>{filteredStudents.map(s => <tr key={s.id}><td><span className="tablePerson"><span className="avatar">{s.name.slice(0, 1).toUpperCase()}</span>{s.name}</span></td><td>{s.rollNumber || '—'}</td><td>{s.email}</td><td><span className={`statusBadge ${String(s.status).toLowerCase()}`}>{s.status}</span></td><td>{new Date(s.createdAt).toLocaleDateString()}</td><td>{s.lastLoginAt ? new Date(s.lastLoginAt).toLocaleString() : 'Never'}</td></tr>)}</tbody></table>{!filteredStudents.length && <p className="empty">No matching student accounts.</p>}</div></>}
    {modal?.type === 'test' && <TestEditor initial={modal.initial} onSave={saveTest} onCancel={() => setModal(null)} />}{modal?.type === 'question' && <QuestionEditor initial={modal.initial} onSave={saveQuestion} onCancel={() => setModal(null)} />}{detail && <ResultDetail data={detail} onClose={() => setDetail(null)} />}
    </main></div>
  </div>;
}

function Stat({ label, value, icon, tone = 'blue', meta }: { label: string; value: string | number; icon?: React.ReactNode; tone?: string; meta?: string }) { return <div className="card stat"><div className="statTop"><small>{label}</small>{icon && <span className={`statIcon ${tone}`}>{icon}</span>}</div><strong>{value}</strong>{meta && <span className="statMeta">{meta}</span>}</div>; }
function ResultDetail({ data, onClose }: { data: any; onClose: () => void }) { return <div className="modal"><div className="card detailCard"><div className="sectionHead"><div><h2>{data.student.name}</h2><p>{data.student.email} · {data.test.title}</p></div><button className="secondary" onClick={onClose}>Close</button></div><div className="resultSummary"><Stat label="Score" value={data.score ?? 0} /><Stat label="Violations" value={data.violationCount} /><Stat label="Questions answered" value={data.questions.filter((q: any) => q.selectedOptionId).length} /></div><h3>Question-wise Review</h3>{data.questions.map((q: any, i: number) => <div className={`review ${q.isCorrect ? 'reviewCorrect' : q.selectedOptionId ? 'reviewWrong' : 'reviewSkipped'}`} key={q.questionId}><b>Q{i + 1}. {q.questionText}</b><p>Your answer: <strong>{q.selectedOptionText || 'Not answered'}</strong></p><p>Correct answer: <strong>{q.correctOptionText}</strong></p>{q.explanation && <small>Explanation: {q.explanation}</small>}</div>)}</div></div>; }

function App() { const [u, setU] = useState<any>(null); const [checked, setChecked] = useState(false); useEffect(() => { api('/api/me').then(setU).catch(() => localStorage.clear()).finally(() => setChecked(true)); }, []); if (!checked) return <main className="center"><p className="muted">Loading account…</p></main>; if (!u) return <Login onLogin={setU} />; return u.role === 'ADMIN' ? <Admin user={u} /> : <Student user={u} />; }
const rootContainer = document.getElementById('root')!;
const rootHolder = window as typeof window & { __examPlatformRoot?: ReturnType<typeof createRoot> };
const appRoot = rootHolder.__examPlatformRoot || createRoot(rootContainer);
rootHolder.__examPlatformRoot = appRoot;
appRoot.render(<App />);
