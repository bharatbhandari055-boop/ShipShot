-- LastMile Ready Dashboard — Supabase schema
-- Run this once in Supabase: Project → SQL Editor → New query → paste → Run.
--
-- Row Level Security is enabled with NO policies on every table, so the
-- Postgres REST API (anon/public key) can't read or write anything.
-- Only the server can, using the service_role key (which bypasses RLS
-- entirely) — same security model as the Firestore rules from before:
-- the browser never talks to the database directly.

create extension if not exists pgcrypto;

create table if not exists registrations (
  uid text primary key,
  name text not null,
  phone text not null,
  email text not null,
  hub text not null,
  city text not null,
  role text not null,
  pin text not null,
  status text not null default 'pending',
  note text,
  category text not null default 'User', -- 'Hope on Wheels' (rider, auto-approved) or 'User' (staff, approval flow)
  submitted_at bigint not null
);
alter table registrations enable row level security;

create table if not exists profiles (
  id text primary key,
  name text,
  phone text,
  email text,
  hub text,
  city text,
  pin text,
  roles text[] not null default '{}',
  status text not null default 'approved',
  category text not null default 'User', -- 'Hope on Wheels' (rider) or 'User' (staff)
  must_change_pin boolean not null default false,
  approved_at bigint,
  updated_at bigint
);
alter table profiles enable row level security;

create table if not exists admins (
  id uuid primary key default gen_random_uuid(),
  username text unique not null,
  pass_hash text not null,
  created_at bigint not null
);
alter table admins enable row level security;

create table if not exists content (
  id uuid primary key default gen_random_uuid(),
  persona text not null,
  topic text not null default 'General', -- module/topic name set at upload time; content sharing a topic is grouped together and shares one assessment
  type text not null,
  title text,
  description text,
  url text,
  required_minutes numeric,
  created_at bigint not null
);
alter table content enable row level security;

-- One assessment per (persona, topic) pair, instead of one per persona.
-- A topic with no content at all still works under the "General" default,
-- which preserves the old "one assessment for the whole persona" behavior.
create table if not exists assessments (
  persona text not null,
  topic text not null default 'General',
  questions jsonb not null default '[]',
  pass_score numeric not null default 80, -- % of scorable (mcq) questions needed to pass
  primary key (persona, topic)
);
alter table assessments enable row level security;

create table if not exists submissions (
  persona text not null,
  topic text not null default 'General',
  uid text not null,
  answers jsonb not null default '{}',
  submitted_at bigint not null,
  passed boolean, -- null if the topic has no scorable (mcq) questions
  primary key (persona, topic, uid)
);
alter table submissions enable row level security;

create table if not exists progress (
  id text primary key, -- slug(persona)+"_"+uid
  persona text not null,
  uid text not null,
  completed jsonb not null default '{}',
  started jsonb not null default '{}', -- contentId -> true, set the moment a user opens an item (used to derive "In Progress" for rider status)
  updated_at bigint not null
);
alter table progress enable row level security;

-- Was already referenced by server.js (bulk-assign, manual assign) but
-- missing from this file — added so a brand-new project has it too.
create table if not exists assignments (
  content_id uuid not null references content(id) on delete cascade,
  uid text not null,
  assigned_at bigint not null,
  due_date bigint,
  primary key (content_id, uid)
);
alter table assignments enable row level security;

-- City -> Hub/DC/FC mapping. Admin-managed (Admin panel), shared by both
-- the rider and staff registration forms and by the city/hub dashboards.
-- One city can have many hubs.
create table if not exists hub_mapping (
  id uuid primary key default gen_random_uuid(),
  city text not null,
  hub text not null,
  created_at bigint not null,
  unique (city, hub)
);
alter table hub_mapping enable row level security;

-- =========================================================
-- MIGRATION — only needed if you already ran the version of this file
-- from before "topic" existed. Safe to run again; every step is
-- idempotent. Skip this whole block on a brand-new project — the
-- create table statements above already include topic.
-- =========================================================

alter table content add column if not exists topic text not null default 'General';

alter table assessments add column if not exists topic text not null default 'General';
do $$
begin
  if exists (
    select 1 from information_schema.table_constraints
    where table_name = 'assessments' and constraint_type = 'PRIMARY KEY'
  ) then
    execute (
      select 'alter table assessments drop constraint ' || constraint_name
      from information_schema.table_constraints
      where table_name = 'assessments' and constraint_type = 'PRIMARY KEY'
      limit 1
    );
  end if;
  alter table assessments add primary key (persona, topic);
exception when others then null;
end $$;

alter table submissions add column if not exists topic text not null default 'General';
alter table submissions drop column if exists id; -- old synthetic id, replaced by the (persona, topic, uid) key below
do $$
begin
  if exists (
    select 1 from information_schema.table_constraints
    where table_name = 'submissions' and constraint_type = 'PRIMARY KEY'
  ) then
    execute (
      select 'alter table submissions drop constraint ' || constraint_name
      from information_schema.table_constraints
      where table_name = 'submissions' and constraint_type = 'PRIMARY KEY'
      limit 1
    );
  end if;
  alter table submissions add primary key (persona, topic, uid);
exception when others then null;
end $$;

-- =========================================================
-- MIGRATION (2) — rider persona, city/hub mapping, pass/fail re-earn,
-- started-state tracking. Safe to re-run.
-- =========================================================
alter table registrations add column if not exists category text not null default 'User';
alter table profiles add column if not exists category text not null default 'User';
alter table profiles add column if not exists must_change_pin boolean not null default false;
alter table assessments add column if not exists pass_score numeric not null default 80;
alter table submissions add column if not exists passed boolean;
alter table progress add column if not exists started jsonb not null default '{}';

create table if not exists assignments (
  content_id uuid not null references content(id) on delete cascade,
  uid text not null,
  assigned_at bigint not null,
  due_date bigint,
  primary key (content_id, uid)
);
alter table assignments enable row level security;

create table if not exists hub_mapping (
  id uuid primary key default gen_random_uuid(),
  city text not null,
  hub text not null,
  created_at bigint not null,
  unique (city, hub)
);
alter table hub_mapping enable row level security;

-- =========================================================
-- MIGRATION (3) — Deploy 1 (Phase 1+2): rider persona removed (the
-- category/must_change_pin columns are left in place, just unused, rather
-- than dropped — harmless, avoids a destructive migration), last-login
-- tracking for the active/inactive graph, single-persona registration
-- (primary_role) + tagging hierarchy, Super Admin tier + forced
-- first-login password change. Safe to re-run.
-- =========================================================
alter table profiles add column if not exists last_login bigint;
alter table profiles add column if not exists primary_role text; -- the ONE persona picked at registration; roles[] can still hold more (admin-granted extra content access) but this is what's shown as their title
alter table profiles add column if not exists tagged_to text; -- uid of the profile this person reports to / is tagged to
alter table profiles add column if not exists access_tier text not null default 'view'; -- 'view' | 'semi_admin' | 'admin', derived from primary_role at approval time (phase 3 enforces it; stored now so it's ready)

alter table registrations add column if not exists primary_role text;
alter table registrations add column if not exists tagged_to text;
alter table registrations add column if not exists tagged_name text; -- denormalized so a pending registration still shows who it's tagged to even before approval

alter table admins add column if not exists tier text not null default 'admin'; -- 'super_admin' | 'admin'
alter table admins add column if not exists must_change_password boolean not null default false;
alter table admins add column if not exists display_name text;
alter table admins add column if not exists updated_at bigint;
-- The bootstrap Super Admin account (Superadmin / 1111) is seeded by
-- server.js on startup, not here — it needs bcryptjs to hash the PIN
-- properly, which SQL can't do on its own.

-- =========================================================
-- MIGRATION (4) — Deploy 2 (Phase 3+4): tagged-person CSV approval,
-- RM admin-tier verification, dynamic registration form fields. Safe to
-- re-run.
-- =========================================================
-- 'admin_pending' sits between approval and full admin access for
-- Regional Managers — Super Admin still has to separately verify them
-- (everyone else's access_tier activates automatically on approval).
-- No schema change needed for that — it's just another value in the
-- existing profiles.access_tier text column.

create table if not exists form_fields (
  id uuid primary key default gen_random_uuid(),
  field_key text unique not null, -- machine key, e.g. "emergency_contact"
  label text not null,            -- shown on the registration form
  type text not null default 'text', -- 'text' | 'number' | 'dropdown' | 'date'
  options jsonb default '[]',     -- for type = 'dropdown'
  required boolean not null default false,
  sort_order int not null default 0,
  created_at bigint not null
);
alter table form_fields enable row level security;

-- Custom field answers, keyed by field_key -> value. Kept even if the
-- field definition is later renamed/removed, so old submissions never
-- silently lose data.
alter table registrations add column if not exists custom_fields jsonb not null default '{}';
alter table profiles add column if not exists custom_fields jsonb not null default '{}';

alter table admins add column if not exists phone text;
alter table admins add column if not exists email text;
