-- GraphOps Supabase schema — run once in the Supabase SQL editor.
-- Tables: hunt history + the analyst approval audit trail (the human gate
-- on irreversible containment actions).

create table if not exists hunt_runs (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz default now(),
  engine_source text,
  node_count int,
  edge_count int,
  finding_count int
);

create table if not exists findings (
  id uuid primary key default gen_random_uuid(),
  hunt_run_id uuid references hunt_runs(id) on delete cascade,
  created_at timestamptz default now(),
  title text not null,
  severity text,
  evidence jsonb,
  nodes jsonb
);

-- Every containment action the analyst approves or rejects is recorded here.
-- Nothing in the app auto-executes; this table is the proof a human decided.
create table if not exists containment_decisions (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz default now(),
  node_id text not null,
  action text not null,
  target text,
  decision text not null check (decision in ('approved', 'rejected')),
  decided_by text default 'analyst',
  rationale text
);

create index if not exists findings_hunt_run_idx on findings (hunt_run_id);
create index if not exists decisions_node_idx on containment_decisions (node_id);

-- Approval queue for irreversible containment actions (the human gate).
-- Reversible actions (observe/enrich/flag) never land here; they are
-- auto-approved as recommendations. Nothing in the app auto-executes.
create table if not exists containment_queue (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz default now(),
  node_id text not null,
  action text not null,
  target text,
  reversibility float,
  impact_tier text,
  est_cost_usd float,
  status text default 'queued_for_approval',
  context jsonb,
  requested_by text default 'analyst'
);

create index if not exists queue_status_idx on containment_queue (status);
