# TaskBoard — Project Management App

A Next.js 15 fullstack application for managing projects, tasks, and team members. TypeScript + Prisma + PostgreSQL on the server, React 19 + TanStack Query on the client.

## Quick Setup (Docker — Recommended)

```bash
# Clone and enter the repo
git clone <repo-url> && cd taskboard

# Start the app and database
docker-compose up --build

# In a separate terminal, set up the database
docker-compose exec web npm run db:seed

# Run the test suite
docker-compose exec web npm test

# The app is now running at http://localhost:3000
```

## Manual Setup (without Docker)

Requires: Node.js 20+, PostgreSQL 15+

```bash
# Run the setup script (installs deps, sets up DB, configures git hooks)
chmod +x bin/setup
./bin/setup

# Or do it manually:
npm install
git config core.hooksPath .git-hooks
cp .env.example .env   # then edit DATABASE_URL if your local Postgres differs
npx prisma migrate deploy
npx prisma generate
npm run db:seed
npm test
npm run dev
```

## AI Tool Conversation Tracking

**This repository is configured to automatically capture your AI coding tool conversation history with each git commit.** This includes conversations from Claude Code, Cursor, Aider, Continue.dev, Cody, Cline, and Windsurf.

This is part of the Ajackus evaluation process. We evaluate how you collaborate with AI tools — your prompting strategy, how you break down problems, and how you review AI suggestions. The captured conversations help us understand your workflow.

**How it works:**
- A pre-commit git hook runs automatically before each commit
- It copies conversation files from AI tool directories (e.g., `.claude/`, `.cursor/`) into `.ai-conversations/`
- These files are staged and included in your commit
- You don't need to do anything — it happens automatically

**What's captured:** Only AI tool conversation logs stored in the project directory. No system files, browsing history, or anything outside this repository.

**If you prefer a tool that doesn't store local conversations** (like browser-based ChatGPT), the screen recording will capture your interactions instead. No additional action needed from you.

## Seed Data

The seed file creates:
- 5 users across 3 projects with different roles (admin / member / viewer)
- 3 projects with realistic task distributions
- 12 tasks spanning all four statuses (`todo`, `in_progress`, `review`, `done`)

All user passwords are: `password123`

| Email | Role on which project |
|-------|----------------------|
| meera@taskboard.dev | admin on Q3 Launch & Internal Tools, member on Onboarding |
| arjun@taskboard.dev | admin on Onboarding, member on Q3 Launch |
| kavya@example.com | member on Q3 Launch |
| dev@example.com | viewer on Q3 Launch |
| lina@example.com | member on Onboarding |

## Authentication

Register or login to get a JWT token:

```bash
# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"meera@taskboard.dev","password":"password123"}'

# Use the returned token
curl -H "Authorization: Bearer <token>" http://localhost:3000/api/projects
```

## API Endpoints

### Auth
- `POST /api/auth/register` — Create account
- `POST /api/auth/login` — Sign in, get JWT
- `GET /api/users/me` — Current user (authenticated)

### Projects
- `GET /api/projects` — List projects you're a member of (authenticated)
- `POST /api/projects` — Create a project (authenticated; creator becomes admin)
- `GET /api/projects/:id` — Project detail with tasks and members (authenticated)
- `PATCH /api/projects/:id` — Update project (authenticated)
- `DELETE /api/projects/:id` — Delete project (authenticated)

### Tasks
- `GET /api/projects/:id/tasks` — List tasks in a project (authenticated)
- `POST /api/projects/:id/tasks` — Create a task (authenticated)
- `PATCH /api/tasks/:id` — Update a task (authenticated)
- `DELETE /api/tasks/:id` — Delete a task (authenticated)

### Airtable Export
- `POST /api/projects/:id/exports` — Start an export to Airtable (admin/member only). Returns the initial snapshot. If an export is already in flight for the project, the existing one is returned instead.
- `GET /api/projects/:id/exports` — List recent export jobs for the project.
- `GET /api/projects/:id/exports/:exportId` — Status snapshot (Redis-first, DB fallback).
- `GET /api/projects/:id/exports/:exportId/errors` — Full per-record error list (cold DB read; called lazily by the UI).

## Airtable Export Setup

The export pushes every task in a project into a real Airtable base using the official `airtable` SDK. Idempotency is handled by Airtable's `performUpsert` keyed on a `TaskBoardId` field, so running the export multiple times never creates duplicates.

### 1. Configure environment

```env
AIRTABLE_API_KEY="pat..."           # personal access token
AIRTABLE_BASE_ID="app..."           # the Airtable base to write to
AIRTABLE_TABLE_NAME="Tasks"         # table within the base (default: Tasks)
REDIS_URL="redis://localhost:6379"
```

### 2. Required Airtable table schema

Create a table named `Tasks` (or whatever `AIRTABLE_TABLE_NAME` is set to) in your base with these fields:

| Field | Type | Notes |
|---|---|---|
| `TaskBoardId` | Single line text | **Upsert key** — must exist. |
| `Title` | Single line text | |
| `Description` | Long text | |
| `Status` | Single select | Options: `todo`, `in_progress`, `review`, `done` |
| `Assignee` | Single line text | Assignee's display name (nullable) |
| `CreatedAt` | Date | |
| `UpdatedAt` | Date | |

Missing fields surface as per-record `422`s in the export's `errors` list; they don't abort the job.

### 3. Run Redis and the worker

The worker is a long-running Node process (BullMQ). Redis is required.

```bash
# Docker (both services come up automatically)
docker compose up

# Or run the worker manually against your local Postgres/Redis
npm run worker          # production-style
npm run worker:dev      # with tsx watch
```

### 4. Trigger the export

Open a project's detail page as an admin or member and click **Export to Airtable**. Use the **Refresh** button on the status card to pull the latest progress — status reads hit Redis with a Postgres fallback, so refreshes stay cheap even under load. When the job is terminal you can re-trigger to run again; the upsert keeps Airtable in sync without duplicating records.

### How resilience is handled

- **Retry policy** — `429` / `5xx` / network errors are retried with exponential backoff (max 5 attempts). `401` / `403` / `404` mark the job `failed` immediately. `422` / `400` at the batch level falls back to per-record upserts so one bad row doesn't take down the other nine.
- **Crash recovery** — the worker writes a cursor (`lastProcessedTaskId`) and running counts to the `ExportJob` row after every batch. On worker restart or BullMQ stall detection, the job is re-picked-up and resumes from the cursor. Replayed batches are no-ops in Airtable thanks to `performUpsert`.
- **Single-flight per project** — `SET NX export:active:{projectId}` in Redis guarantees only one export runs at a time per project; concurrent POSTs return the already-running job.

## Tech Stack

- Node.js 20 (runtime)
- Next.js 15 (App Router) / React 19
- TypeScript 5 (strict mode)
- Prisma 6 + PostgreSQL 16
- TanStack Query 5 (client data)
- Zod 3 (schema validation)
- Tailwind CSS 3
- bcryptjs + jsonwebtoken
- BullMQ + ioredis (background export worker)
- airtable (official SDK) for the export target
- Vitest 2 (testing)
