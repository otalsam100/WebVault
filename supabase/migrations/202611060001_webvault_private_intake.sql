-- WebVault private customer intake foundation
-- Run in Supabase SQL Editor. Customer data is never readable by anon/authenticated users.

create extension if not exists pgcrypto;

create table if not exists public.webvault_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.customer_requests (
  id uuid primary key default gen_random_uuid(),
  customer_name text not null,
  contact text not null,
  business text,
  message text,
  status text not null default 'new' check (status in ('new','in_progress','completed','archived')),
  created_at timestamptz not null default now()
);

create table if not exists public.request_files (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null references public.customer_requests(id) on delete cascade,
  storage_path text not null unique,
  original_name text not null,
  content_type text not null,
  size_bytes bigint not null check (size_bytes > 0),
  created_at timestamptz not null default now()
);

create table if not exists public.webvault_submission_limits (
  ip_hash text not null,
  created_at timestamptz not null default now()
);
create index if not exists webvault_submission_limits_created_idx
  on public.webvault_submission_limits (created_at);
create index if not exists customer_requests_created_idx
  on public.customer_requests (created_at desc);
create index if not exists request_files_request_idx
  on public.request_files (request_id);

create or replace function public.webvault_is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.webvault_admins
    where user_id = auth.uid()
  );
$$;

alter table public.webvault_admins enable row level security;
alter table public.customer_requests enable row level security;
alter table public.request_files enable row level security;
alter table public.webvault_submission_limits enable row level security;

drop policy if exists "Admins can view own admin record" on public.webvault_admins;
create policy "Admins can view own admin record"
  on public.webvault_admins for select to authenticated
  using (user_id = auth.uid());

drop policy if exists "Admins can read customer requests" on public.customer_requests;
create policy "Admins can read customer requests"
  on public.customer_requests for select to authenticated
  using (public.webvault_is_admin());

drop policy if exists "Admins can update customer requests" on public.customer_requests;
create policy "Admins can update customer requests"
  on public.customer_requests for update to authenticated
  using (public.webvault_is_admin())
  with check (public.webvault_is_admin());

drop policy if exists "Admins can delete customer requests" on public.customer_requests;
create policy "Admins can delete customer requests"
  on public.customer_requests for delete to authenticated
  using (public.webvault_is_admin());

drop policy if exists "Admins can read request files" on public.request_files;
create policy "Admins can read request files"
  on public.request_files for select to authenticated
  using (public.webvault_is_admin());

drop policy if exists "Admins can delete request files" on public.request_files;
create policy "Admins can delete request files"
  on public.request_files for delete to authenticated
  using (public.webvault_is_admin());

-- No client insert policies are intentionally created. Public submissions go through
-- the server-side Edge Function, which uses the service-role key stored in Supabase secrets.

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'webvault-private-uploads',
  'webvault-private-uploads',
  false,
  26214400,
  array['image/jpeg','image/png','image/webp','image/heic','video/mp4','video/quicktime','video/webm']
)
on conflict (id) do update set
  public = false,
  file_size_limit = 26214400,
  allowed_mime_types = excluded.allowed_mime_types;

create or replace function public.webvault_allow_submission(p_ip_hash text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  recent_count integer;
begin
  delete from public.webvault_submission_limits
    where created_at < now() - interval '2 days';

  select count(*) into recent_count
    from public.webvault_submission_limits
    where ip_hash = p_ip_hash
      and created_at > now() - interval '1 hour';

  if recent_count >= 5 then
    return false;
  end if;

  insert into public.webvault_submission_limits(ip_hash) values (p_ip_hash);
  return true;
end;
$$;

revoke all on function public.webvault_allow_submission(text) from public, anon, authenticated;
grant execute on function public.webvault_allow_submission(text) to service_role;
revoke all on function public.webvault_is_admin() from public, anon;
grant execute on function public.webvault_is_admin() to authenticated;

-- Add your own Auth user's UUID to webvault_admins after creating your account.
-- Never add a public INSERT policy to this table.
