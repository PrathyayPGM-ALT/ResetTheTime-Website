-- Reset The Time - mod portal Supabase setup.
-- Run this once in your Supabase project: Dashboard -> SQL Editor -> paste -> Run.
-- (Uses the same project as your game leaderboard, or any project you like.)

-- 1) Metadata table -----------------------------------------------------
create table if not exists public.mods (
    id          text primary key,
    name        text not null,
    author      text not null default 'unknown',
    version     text,
    description text,
    sha256      text,
    size        integer,
    uploaded_at timestamptz not null default now(),
    downloads   integer not null default 0,
    scan        jsonb
);

-- The website talks to this table with the SERVICE ROLE key, which bypasses
-- RLS. We still enable RLS and add a public read policy so anon clients (e.g.
-- the game hitting /api/mods indirectly, or direct reads) can list mods but
-- never write.
alter table public.mods enable row level security;

drop policy if exists "mods public read" on public.mods;
create policy "mods public read"
    on public.mods for select
    to anon, authenticated
    using (true);

-- 2) Storage bucket for the .rttmod files -------------------------------
insert into storage.buckets (id, name, public)
values ('mods', 'mods', true)
on conflict (id) do update set public = true;

-- Public read of objects in the 'mods' bucket (downloads via public URL).
drop policy if exists "mods bucket public read" on storage.objects;
create policy "mods bucket public read"
    on storage.objects for select
    to anon, authenticated
    using (bucket_id = 'mods');

-- Uploads/updates are done server-side with the service role key, so no
-- anon insert/update policy is added on purpose (only the vetted uploader
-- that has passed scanning can write).
