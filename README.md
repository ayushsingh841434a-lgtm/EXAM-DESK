# Online Exam Platform — Admin Dashboard Edition

A runnable full-stack exam platform with a proper admin dashboard and student exam flow.

## Admin dashboard

After logging in as admin you get:

- Dashboard statistics
- Tests: create, edit, delete, Allow/Resume/Pause/End
- Questions: select a test, add/edit/delete 4-option MCQs, marks, negative marks, explanations
- Live Monitoring: active students, time remaining, violation counts, auto-refresh
- Results: filter by test, score/correct/wrong/skipped/violations
- Student-wise Detailed Result: every question, student's answer, correct answer and explanation

Destructive deletes are blocked after student attempts exist so submitted exam history is not silently destroyed.

## Run with Docker

1. Install Docker Desktop.
2. Optional: copy `.env.example` to `.env` and change credentials/secrets.
3. Run:

```bash
docker compose up --build
```

Open `http://localhost:3000`.

Default admin:

- Email: `admin@example.com`
- Password: `Admin12345!`

Change these before any real deployment.

## Local development

Install dependencies and build both apps from the repository root:

```bash
npm install
npm run build
```

On Windows, stop any running development servers before reinstalling dependencies so native build files are not locked. The root build regenerates Prisma Client before compiling both applications.

Prepare the backend database and Prisma client from the repository root:

```bash
npm run prisma:generate --workspace=exam-platform-api
npm run prisma:push --workspace=exam-platform-api
npm run seed --workspace=exam-platform-api
```

Start both servers together from the repository root:

```bash
npm run dev
```

Open the frontend URL printed by Vite (normally `http://localhost:3000`; Vite selects the next available port if that port is occupied). To run one service separately, use `npm run dev:backend` or `npm run dev:frontend`.

Set `VITE_API_URL=http://localhost:8080` if needed.

## Student registration

Students register with full name, roll number, email, and password. Email and roll number are normalized and unique. For local development, open the returned dev verification path, then use all four credentials at student login. Admin login remains email/password based.

### Password reset email

Configure the following backend environment variables to enable password-reset email. Copy `backend/.env.example` as a starting point and use real SMTP credentials; do not commit secrets.

- `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`
- `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`
- `OTP_HASH_SECRET` (a long random secret, separate from `JWT_SECRET`)

Password reset uses a six-digit OTP expiring after 10 minutes, one-time verification, five verification attempts, a 60-second resend cooldown, and at most three requests per student within 15 minutes. OTPs and reset tokens are stored as hashes. The forgot-password response is generic whether or not the account matches.

Authentication endpoints are under `/api/auth`:

- `POST /student/login`
- `POST /forgot-password/request`
- `POST /forgot-password/verify-otp`
- `POST /forgot-password/reset`
- `POST /logout`

Student admin details are available at `GET /api/admin/students`; password hashes are never selected or returned.

### Database schema updates

This repository has no Prisma migration history and uses `prisma db push` for schema changes. Apply the current schema with `cd backend && npm run prisma:push`, then regenerate the client with `npm run prisma:generate`. The authentication schema was synced to the configured local database during implementation.

### Authentication tests

Run backend security tests with `cd backend && npm test`; build with `cd backend && npm run build`.

## 1000+ students

The Docker setup keeps two API instances behind Nginx and uses PostgreSQL + Redis. Use the included k6 script for staged load testing. Passing a 1000 VU test is not a guarantee of production capacity; size infrastructure from measured CPU, memory, database and Redis metrics.

## Browser anti-cheating limitation

The platform logs tab switching, focus loss, fullscreen exit and common copy/print shortcuts. Browser JavaScript cannot guarantee prevention of screenshots, screen recording, another device, or every developer-tool method.
