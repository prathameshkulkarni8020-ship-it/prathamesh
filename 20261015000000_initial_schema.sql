-- BandhPremache initial schema. Apply only to a new Supabase project after review.
create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

create table public.user_roles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('OWNER', 'DEVELOPER', 'MODERATOR', 'MEMBER')),
  is_active boolean not null default true,
  assigned_by uuid references auth.users(id) on delete set null,
  assigned_at timestamptz not null default now()
);

create table public.admin_permissions (
  user_id uuid not null references auth.users(id) on delete cascade,
  permission text not null check (permission in (
    'business.dashboard.read', 'business.plans.manage', 'business.payments.read',
    'business.accounts.manage', 'business.admins.manage', 'business.audit.read',
    'trust.reports.read', 'trust.reports.manage', 'trust.accounts.manage',
    'technical.diagnostics.read'
  )),
  granted_by uuid references auth.users(id) on delete set null,
  granted_at timestamptz not null default now(),
  primary key (user_id, permission)
);

create function public.has_permission(requested_permission text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.user_roles r
    where r.user_id = auth.uid() and r.is_active and r.role = 'OWNER'
  ) or exists (
    select 1
    from public.admin_permissions p
    join public.user_roles r on r.user_id = p.user_id and r.is_active
    where p.user_id = auth.uid() and p.permission = requested_permission and r.role <> 'MEMBER'
  );
$$;

revoke all on function public.has_permission(text) from public, anon;
grant execute on function public.has_permission(text) to authenticated;

create table public.profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null check (char_length(display_name) between 2 and 80),
  birth_date date not null check (birth_date <= (current_date - interval '18 years')::date),
  gender text not null check (gender in ('woman', 'man', 'nonbinary', 'prefer_not_to_say')),
  marital_status text not null check (marital_status in ('never_married', 'divorced', 'widowed', 'separated')),
  religion text check (religion is null or char_length(religion) <= 80),
  caste text check (caste is null or char_length(caste) <= 80),
  city text check (city is null or char_length(city) <= 80),
  education text check (education is null or char_length(education) <= 120),
  occupation text check (occupation is null or char_length(occupation) <= 120),
  description text check (description is null or char_length(description) <= 1200),
  visibility text not null default 'private' check (visibility in ('private', 'public')),
  account_status text not null default 'active' check (account_status in ('active', 'suspended', 'banned', 'deletion_review')),
  suspended_until timestamptz,
  last_active_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.profiles add constraint profile_suspension_expiry_consistency
  check ((account_status = 'suspended' and suspended_until is not null) or (account_status <> 'suspended' and suspended_until is null));

create or replace function public.has_permission(requested_permission text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.user_roles r
    join public.profiles profile on profile.user_id = r.user_id and profile.account_status = 'active'
    where r.user_id = auth.uid() and r.is_active and r.role = 'OWNER'
  ) or exists (
    select 1
    from public.admin_permissions p
    join public.user_roles r on r.user_id = p.user_id and r.is_active and r.role <> 'MEMBER'
    join public.profiles profile on profile.user_id = r.user_id and profile.account_status = 'active'
    where p.user_id = auth.uid()
      and (
        p.permission = requested_permission
        or (r.role = 'DEVELOPER' and requested_permission = 'technical.diagnostics.read')
        or (r.role = 'MODERATOR' and requested_permission in ('trust.reports.read', 'trust.reports.manage', 'trust.accounts.manage'))
      )
  );
$$;
revoke all on function public.has_permission(text) from public, anon;
grant execute on function public.has_permission(text) to authenticated;

-- Public discovery exposes age, not birth date or account/security metadata.
create view public.discoverable_profiles with (security_barrier = true) as
select user_id, display_name,
       extract(year from age(current_date, birth_date))::integer as age,
       gender, marital_status, religion, caste, city, education, occupation, description
from public.profiles
where visibility = 'public' and account_status = 'active'
  and exists (
    select 1 from public.profiles viewer
    where viewer.user_id = auth.uid() and viewer.account_status = 'active'
  );
grant select on public.discoverable_profiles to authenticated;

create index profiles_discovery_idx on public.profiles (visibility, account_status, birth_date, city);
create index profiles_inactivity_review_idx on public.profiles (last_active_at)
  where account_status = 'active';

create function public.create_profile_for_new_user()
returns trigger
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  profile_birth_date date;
  profile_name text;
begin
  profile_name := left(trim(coalesce(new.raw_user_meta_data ->> 'display_name', '')), 80);
  begin
    profile_birth_date := nullif(new.raw_user_meta_data ->> 'birth_date', '')::date;
  exception when others then
    raise exception 'A valid date of birth is required.';
  end;

  if char_length(profile_name) < 2 then
    raise exception 'A valid profile name is required.';
  end if;
  if profile_birth_date is null or profile_birth_date > (current_date - interval '18 years')::date then
    raise exception 'You must be at least 18 years old to create an account.';
  end if;

  insert into public.profiles (user_id, display_name, birth_date, gender, marital_status)
  values (new.id, profile_name, profile_birth_date, 'prefer_not_to_say', 'never_married');
  insert into public.user_roles (user_id, role) values (new.id, 'MEMBER');
  return new;
end;
$$;

create trigger auth_user_profile_after_insert
after insert on auth.users
for each row execute function public.create_profile_for_new_user();

create function public.set_updated_at()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

create trigger profiles_set_updated_at before update on public.profiles
for each row execute function public.set_updated_at();

create table public.memberships (
  id uuid primary key default extensions.gen_random_uuid(),
  user_id uuid references auth.users(id) on delete set null,
  status text not null check (status in ('trial', 'active', 'expired', 'cancelled')),
  started_at timestamptz not null,
  ends_at timestamptz not null,
  price_minor bigint not null check (price_minor >= 0),
  currency char(3) not null default 'INR',
  plan_name_snapshot text not null,
  created_at timestamptz not null default now(),
  check (ends_at > started_at)
);
create index memberships_user_status_idx on public.memberships (user_id, status, ends_at desc);

create table public.trial_claims (
  user_id uuid primary key references auth.users(id) on delete cascade,
  started_at timestamptz not null,
  ends_at timestamptz not null,
  check (ends_at > started_at)
);

create function public.start_free_trial()
returns uuid
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  current_user_id uuid := auth.uid();
  new_membership_id uuid;
  started timestamptz := now();
begin
  perform pg_advisory_xact_lock(hashtext(current_user_id::text)::bigint);
  if current_user_id is null then
    raise exception 'Authentication is required.';
  end if;
  if not exists (
    select 1 from auth.users u where u.id = current_user_id and u.email_confirmed_at is not null
  ) then
    raise exception 'Verify your email before starting a trial.';
  end if;
  if not exists (
    select 1 from public.profiles p where p.user_id = current_user_id and p.account_status = 'active'
  ) then
    raise exception 'This account is not eligible to start a trial.';
  end if;
  if exists (select 1 from public.trial_claims t where t.user_id = current_user_id) then
    raise exception 'A trial has already been used for this account.';
  end if;
  if exists (select 1 from public.memberships m
             where m.user_id = current_user_id and m.status in ('active', 'trial') and m.ends_at > started) then
    raise exception 'An active membership already exists.';
  end if;

  insert into public.memberships (user_id, status, started_at, ends_at, price_minor, currency, plan_name_snapshot)
  values (current_user_id, 'trial', started, started + interval '7 days', 0, 'INR', '7-day free trial')
  returning id into new_membership_id;
  insert into public.trial_claims (user_id, started_at, ends_at)
  values (current_user_id, started, started + interval '7 days');
  return new_membership_id;
end;
$$;
revoke all on function public.start_free_trial() from public, anon;
grant execute on function public.start_free_trial() to authenticated;

create table public.membership_plans (
  id uuid primary key default extensions.gen_random_uuid(),
  name text not null check (char_length(name) between 2 and 80),
  description text not null default '' check (char_length(description) <= 1000),
  price_minor bigint not null check (price_minor >= 0),
  currency char(3) not null default 'INR',
  duration_days integer not null check (duration_days between 1 and 3650),
  benefits jsonb not null default '[]'::jsonb check (jsonb_typeof(benefits) = 'array'),
  enabled boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.plan_price_history (
  id uuid primary key default extensions.gen_random_uuid(),
  plan_id uuid not null references public.membership_plans(id) on delete restrict,
  price_minor bigint not null check (price_minor >= 0),
  currency char(3) not null,
  effective_at timestamptz not null default now(),
  changed_by uuid references auth.users(id) on delete set null
);
create index plan_price_history_plan_date_idx on public.plan_price_history (plan_id, effective_at desc);

create function public.audit_plan_price()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if tg_op = 'INSERT' or new.price_minor is distinct from old.price_minor or new.currency is distinct from old.currency then
    insert into public.plan_price_history (plan_id, price_minor, currency, changed_by)
    values (new.id, new.price_minor, new.currency, auth.uid());
  end if;
  return new;
end;
$$;

create table public.payments (
  id uuid primary key default extensions.gen_random_uuid(),
  user_id uuid references auth.users(id) on delete set null,
  membership_id uuid references public.memberships(id) on delete set null,
  provider text not null check (char_length(provider) between 2 and 40),
  provider_reference text not null,
  status text not null check (status in ('pending', 'verified', 'failed', 'refunded')),
  amount_minor bigint not null check (amount_minor >= 0),
  currency char(3) not null,
  created_at timestamptz not null default now(),
  verified_at timestamptz,
  unique (provider, provider_reference)
);
create index payments_verified_date_idx on public.payments (created_at desc) where status = 'verified';

create table public.harassment_reports (
  id uuid primary key default extensions.gen_random_uuid(),
  reporter_id uuid references auth.users(id) on delete set null,
  reported_user_id uuid not null,
  reason text not null check (reason in ('harassment', 'impersonation', 'inappropriate_conduct', 'fraud', 'threats', 'other')),
  description text not null default '' check (char_length(description) <= 2000),
  content_reference text not null default '' check (char_length(content_reference) <= 500),
  assigned_to uuid references auth.users(id) on delete set null,
  status text not null default 'pending' check (status in ('pending', 'assigned', 'reviewing', 'resolved', 'dismissed', 'appealed')),
  decision text check (decision is null or decision in ('no_action', 'warning', 'temporary_suspension', 'ban')),
  decision_rationale text check (decision_rationale is null or char_length(decision_rationale) <= 2000),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (reporter_id is null or reporter_id <> reported_user_id)
);
create unique index harassment_reports_open_duplicate_idx
  on public.harassment_reports (reporter_id, reported_user_id)
  where status in ('pending', 'assigned', 'reviewing') and reporter_id is not null;
create index harassment_reports_queue_idx on public.harassment_reports (status, created_at);

create function public.submit_harassment_report(
  target_user_id uuid,
  report_reason text,
  report_description text default '',
  report_content_reference text default ''
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  current_user_id uuid := auth.uid();
  report_id uuid;
begin
  perform pg_advisory_xact_lock(hashtext(current_user_id::text)::bigint);
  if current_user_id is null then
    raise exception 'Authentication is required.';
  end if;
  if current_user_id = target_user_id then
    raise exception 'You cannot report your own account.';
  end if;
  if report_reason not in ('harassment', 'impersonation', 'inappropriate_conduct', 'fraud', 'threats', 'other') then
    raise exception 'Choose a valid report reason.';
  end if;
  if char_length(coalesce(report_description, '')) > 2000 or char_length(coalesce(report_content_reference, '')) > 500 then
    raise exception 'Report details are too long.';
  end if;
  if not exists (
    select 1 from public.profiles p where p.user_id = current_user_id and p.account_status = 'active'
  ) then
    raise exception 'This account cannot submit reports.';
  end if;
  if not exists (
    select 1 from public.profiles p where p.user_id = target_user_id and p.account_status = 'active'
  ) then
    raise exception 'The reported profile is unavailable.';
  end if;
  if (select count(*) from public.harassment_reports r
      where r.reporter_id = current_user_id and r.created_at > now() - interval '1 hour') >= 5 then
    raise exception 'The hourly report limit has been reached.';
  end if;

  insert into public.harassment_reports (reporter_id, reported_user_id, reason, description, content_reference)
  values (current_user_id, target_user_id, report_reason, coalesce(report_description, ''), coalesce(report_content_reference, ''))
  returning id into report_id;
  return report_id;
exception
  when unique_violation then
    raise exception 'An open report for this profile already exists.';
end;
$$;
revoke all on function public.submit_harassment_report(uuid, text, text, text) from public, anon;
grant execute on function public.submit_harassment_report(uuid, text, text, text) to authenticated;

create function public.decide_harassment_report(
  target_report_id uuid,
  report_decision text,
  rationale text,
  suspension_days integer default null
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  report_record public.harassment_reports%rowtype;
  action_name text;
  expiry timestamptz;
begin
  if not public.has_permission('trust.reports.manage') then
    raise exception 'Permission denied.';
  end if;
  if report_decision not in ('no_action', 'warning', 'temporary_suspension', 'ban') then
    raise exception 'Choose a valid moderation decision.';
  end if;
  if char_length(trim(coalesce(rationale, ''))) < 3 or char_length(rationale) > 2000 then
    raise exception 'A decision reason between 3 and 2000 characters is required.';
  end if;
  if report_decision = 'temporary_suspension' and (suspension_days is null or suspension_days < 1 or suspension_days > 30) then
    raise exception 'Temporary suspension must be between 1 and 30 days.';
  end if;
  if report_decision <> 'temporary_suspension' and suspension_days is not null then
    raise exception 'Suspension duration is only valid for temporary suspensions.';
  end if;

  select * into report_record from public.harassment_reports
  where id = target_report_id for update;
  if not found or report_record.status not in ('pending', 'assigned', 'reviewing', 'appealed') then
    raise exception 'This report is unavailable or already resolved.';
  end if;
  if report_record.assigned_to is distinct from auth.uid() then
    raise exception 'Assign this report to yourself before recording a decision.';
  end if;
  if exists (
    select 1 from public.user_roles r
    where r.user_id = report_record.reported_user_id and r.is_active and r.role in ('OWNER', 'DEVELOPER', 'MODERATOR')
  ) and not public.has_permission('business.admins.manage') then
    raise exception 'Only the Owner can moderate an administrator account.';
  end if;

  if report_decision = 'temporary_suspension' then
    action_name := 'temporary_suspension';
    expiry := now() + make_interval(days => suspension_days);
    update public.profiles set account_status = 'suspended', suspended_until = expiry
    where user_id = report_record.reported_user_id and account_status <> 'banned';
    if not found then raise exception 'The reported account cannot be suspended.'; end if;
  elsif report_decision = 'ban' then
    action_name := 'ban';
    update public.profiles set account_status = 'banned', suspended_until = null
    where user_id = report_record.reported_user_id and account_status <> 'banned';
    if not found then raise exception 'The reported account cannot be banned.'; end if;
  elsif report_decision = 'warning' then
    action_name := 'warning';
  else
    action_name := 'no_action';
  end if;

  update public.harassment_reports
  set assigned_to = coalesce(assigned_to, auth.uid()),
      status = case when report_decision = 'no_action' then 'dismissed' else 'resolved' end,
      decision = report_decision,
      decision_rationale = trim(rationale),
      updated_at = now()
  where id = target_report_id;

  insert into public.moderation_actions (report_id, target_user_id, actor_id, action, reason, expires_at)
  values (target_report_id, report_record.reported_user_id, auth.uid(), action_name, trim(rationale), expiry);
end;
$$;
revoke all on function public.decide_harassment_report(uuid, text, text, integer) from public, anon;
grant execute on function public.decide_harassment_report(uuid, text, text, integer) to authenticated;

create function public.claim_harassment_report(target_report_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.has_permission('trust.reports.manage') then raise exception 'Permission denied.'; end if;
  update public.harassment_reports
  set assigned_to = auth.uid(), status = 'assigned', updated_at = now()
  where id = target_report_id
    and status in ('pending', 'assigned', 'reviewing', 'appealed')
    and (assigned_to is null or assigned_to = auth.uid());
  if not found then raise exception 'This report is already assigned or unavailable.'; end if;
end;
$$;
revoke all on function public.claim_harassment_report(uuid) from public, anon;
grant execute on function public.claim_harassment_report(uuid) to authenticated;

create function public.restore_member_account(target_user_id uuid, restoration_reason text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not (public.has_permission('trust.accounts.manage') or public.has_permission('business.accounts.manage')) then
    raise exception 'Permission denied.';
  end if;
  if char_length(trim(coalesce(restoration_reason, ''))) < 3 or char_length(restoration_reason) > 2000 then
    raise exception 'A restoration reason is required.';
  end if;
  if exists (
    select 1 from public.user_roles r
    where r.user_id = target_user_id and r.is_active and r.role in ('OWNER', 'DEVELOPER', 'MODERATOR')
  ) and not public.has_permission('business.admins.manage') then
    raise exception 'Only the Owner can restore an administrator account.';
  end if;
  update public.profiles set account_status = 'active', suspended_until = null
  where user_id = target_user_id and account_status in ('suspended', 'banned', 'deletion_review');
  if not found then raise exception 'This account is unavailable or already active.'; end if;
  insert into public.moderation_actions (target_user_id, actor_id, action, reason)
  values (target_user_id, auth.uid(), 'restore', trim(restoration_reason));
end;
$$;
revoke all on function public.restore_member_account(uuid, text) from public, anon;
grant execute on function public.restore_member_account(uuid, text) to authenticated;

create function public.refresh_member_account_status()
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  current_user_id uuid := auth.uid();
  effective_status text;
begin
  if current_user_id is null then raise exception 'Authentication is required.'; end if;
  update public.profiles set account_status = 'active', suspended_until = null
  where user_id = current_user_id and account_status = 'suspended' and suspended_until <= now();
  update public.profiles set last_active_at = now()
  where user_id = current_user_id and account_status = 'active'
    and last_active_at < now() - interval '15 minutes';
  select account_status into effective_status from public.profiles where user_id = current_user_id;
  return effective_status;
end;
$$;
revoke all on function public.refresh_member_account_status() from public, anon;
grant execute on function public.refresh_member_account_status() to authenticated;

create table public.moderation_actions (
  id uuid primary key default extensions.gen_random_uuid(),
  report_id uuid references public.harassment_reports(id) on delete set null,
  target_user_id uuid not null,
  actor_id uuid references auth.users(id) on delete set null,
  action text not null check (action in ('no_action', 'warning', 'temporary_suspension', 'ban', 'restore', 'appeal_received')),
  reason text not null check (char_length(reason) between 3 and 2000),
  expires_at timestamptz,
  created_at timestamptz not null default now()
);
create table public.account_deletion_reviews (
  id uuid primary key default extensions.gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  requested_by uuid references auth.users(id) on delete set null,
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected', 'completed')),
  reason text not null default '' check (char_length(reason) <= 1000),
  reviewed_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  reviewed_at timestamptz
);
create unique index account_deletion_review_one_pending_idx on public.account_deletion_reviews (user_id)
  where status in ('pending', 'approved');

create table public.audit_log (
  id bigint generated always as identity primary key,
  actor_id uuid references auth.users(id) on delete set null,
  action text not null,
  target_type text not null,
  target_id text,
  reason text,
  before_values jsonb,
  after_values jsonb,
  created_at timestamptz not null default now()
);
create index audit_log_created_at_idx on public.audit_log (created_at desc);

create function public.audit_admin_row()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  old_data jsonb;
  new_data jsonb;
  row_id text;
  action_reason text;
begin
  old_data := case when tg_op <> 'INSERT' then to_jsonb(old) else null end;
  new_data := case when tg_op <> 'DELETE' then to_jsonb(new) else null end;
  if tg_table_name = 'harassment_reports' then
    old_data := case when old_data is null then null else jsonb_build_object(
      'id', old_data -> 'id', 'status', old_data -> 'status',
      'assigned_to', old_data -> 'assigned_to', 'decision', old_data -> 'decision',
      'decision_rationale', old_data -> 'decision_rationale'
    ) end;
    new_data := case when new_data is null then null else jsonb_build_object(
      'id', new_data -> 'id', 'status', new_data -> 'status',
      'assigned_to', new_data -> 'assigned_to', 'decision', new_data -> 'decision',
      'decision_rationale', new_data -> 'decision_rationale'
    ) end;
  elsif tg_table_name = 'account_deletion_reviews' then
    old_data := case when old_data is null then null else jsonb_build_object('id', old_data -> 'id', 'status', old_data -> 'status') end;
    new_data := case when new_data is null then null else jsonb_build_object('id', new_data -> 'id', 'status', new_data -> 'status') end;
  elsif tg_table_name = 'reviews' then
    old_data := case when old_data is null then null else jsonb_build_object('id', old_data -> 'id', 'status', old_data -> 'status') end;
    new_data := case when new_data is null then null else jsonb_build_object('id', new_data -> 'id', 'status', new_data -> 'status') end;
  end if;
  row_id := coalesce(new_data ->> 'id', new_data ->> 'user_id', old_data ->> 'id', old_data ->> 'user_id');
  action_reason := coalesce(new_data ->> 'decision_rationale', new_data ->> 'reason');
  insert into public.audit_log (actor_id, action, target_type, target_id, reason, before_values, after_values)
  values (auth.uid(), lower(tg_op) || ':' || tg_table_name, tg_table_name, row_id, action_reason, old_data, new_data);
  if tg_op = 'DELETE' then
    return old;
  end if;
  return new;
end;
$$;

create function public.audit_profile_status()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if old.account_status is distinct from new.account_status then
    insert into public.audit_log (actor_id, action, target_type, target_id, before_values, after_values)
    values (
      auth.uid(), 'account_status_changed', 'profiles', new.user_id::text,
      jsonb_build_object('account_status', old.account_status),
      jsonb_build_object('account_status', new.account_status)
    );
  end if;
  return new;
end;
$$;

create table public.reviews (
  id uuid primary key default extensions.gen_random_uuid(),
  user_id uuid references auth.users(id) on delete set null,
  display_name text not null check (char_length(display_name) between 2 and 80),
  body text not null check (char_length(body) between 10 and 1200),
  permission_to_publish boolean not null default false,
  status text not null default 'pending' check (status in ('pending', 'published', 'rejected')),
  created_at timestamptz not null default now()
);
create unique index reviews_one_per_member_idx on public.reviews (user_id) where user_id is not null;
create view public.published_reviews with (security_barrier = true) as
select id, display_name, body, created_at
from public.reviews
where status = 'published' and permission_to_publish;
grant select on public.published_reviews to anon, authenticated;

create table public.contact_messages (
  id uuid primary key default extensions.gen_random_uuid(),
  name text not null check (char_length(name) between 2 and 100),
  email text not null check (char_length(email) <= 254),
  message text not null check (char_length(message) between 10 and 3000),
  created_at timestamptz not null default now()
);

create function public.submit_contact_message(sender_name text, sender_email text, message_body text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  perform pg_advisory_xact_lock(519004221);
  if char_length(trim(coalesce(sender_name, ''))) not between 2 and 100
     or char_length(trim(coalesce(sender_email, ''))) not between 3 and 254
     or sender_email !~* '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
     or char_length(trim(coalesce(message_body, ''))) not between 10 and 3000 then
    raise exception 'Check your contact details and message.';
  end if;
  if (select count(*) from public.contact_messages where created_at > now() - interval '1 hour') >= 100
     or (select count(*) from public.contact_messages
         where lower(email) = lower(trim(sender_email)) and created_at > now() - interval '1 hour') >= 3 then
    raise exception 'Contact message rate limit reached.';
  end if;
  insert into public.contact_messages (name, email, message)
  values (trim(sender_name), lower(trim(sender_email)), trim(message_body));
end;
$$;
revoke all on function public.submit_contact_message(text, text, text) from public;
grant execute on function public.submit_contact_message(text, text, text) to anon, authenticated;

create function public.admin_dashboard_summary()
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  result jsonb;
begin
  if not public.has_permission('business.dashboard.read') then
    raise exception 'Permission denied.';
  end if;

  with latest_memberships as (
    select distinct on (m.user_id) m.user_id, m.status, m.ends_at
    from public.memberships m
    where m.user_id is not null
    order by m.user_id, m.started_at desc, m.created_at desc
  )
  select jsonb_build_object(
    'members', jsonb_build_object(
      'total', (select count(*) from public.profiles),
      'active', (select count(*) from public.profiles where account_status = 'active'),
      'free', (
        select count(*) from public.profiles p
        where p.account_status = 'active'
          and not exists (select 1 from latest_memberships m
                          where m.user_id = p.user_id and m.status in ('active', 'trial') and m.ends_at > now())
      ),
      'trial', (select count(*) from latest_memberships where status = 'trial' and ends_at > now()),
      'paid', (select count(*) from latest_memberships where status = 'active' and ends_at > now()),
      'expired', (select count(*) from latest_memberships where status in ('active', 'trial') and ends_at <= now())
    ),
    'pending_reports', (select count(*) from public.harassment_reports where status in ('pending', 'assigned', 'reviewing')),
    'inactive_free_accounts', (
      select count(*) from public.profiles p
      where p.account_status = 'active' and p.last_active_at < now() - interval '6 months'
        and not exists (select 1 from latest_memberships m
                        where m.user_id = p.user_id and m.status in ('active', 'trial') and m.ends_at > now())
    ),
    'upcoming_expirations', coalesce((
      select jsonb_agg(jsonb_build_object(
        'member', p.display_name, 'expires_at', m.ends_at, 'status', m.status
      ) order by m.ends_at)
      from (
        select user_id, status, ends_at
        from latest_memberships
        where status in ('active', 'trial') and ends_at > now() and ends_at < now() + interval '10 days'
        order by ends_at limit 10
      ) m join public.profiles p on p.user_id = m.user_id
    ), '[]'::jsonb),
    'verified_payments', coalesce((
      select jsonb_agg(jsonb_build_object(
        'amount_minor', p.amount_minor, 'currency', p.currency, 'verified_at', p.verified_at
      ) order by p.verified_at desc)
      from (select amount_minor, currency, verified_at from public.payments
            where status = 'verified' order by verified_at desc limit 10) p
    ), '[]'::jsonb),
    'revenue_by_currency', coalesce((
      select jsonb_agg(jsonb_build_object('currency', totals.currency, 'amount_minor', totals.amount_minor))
      from (
        select currency, sum(amount_minor) as amount_minor
        from public.payments where status = 'verified'
        group by currency order by currency
      ) totals
    ), '[]'::jsonb)
  ) into result;

  return result;
end;
$$;
revoke all on function public.admin_dashboard_summary() from public, anon;
grant execute on function public.admin_dashboard_summary() to authenticated;

create function public.health_check()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select public.has_permission('technical.diagnostics.read');
$$;
revoke all on function public.health_check() from public, anon;
grant execute on function public.health_check() to authenticated;

create trigger membership_plans_set_updated_at before update on public.membership_plans
for each row execute function public.set_updated_at();
create trigger membership_plans_audit_price after insert or update of price_minor, currency on public.membership_plans
for each row execute function public.audit_plan_price();
create trigger membership_plans_audit_admin after insert or update or delete on public.membership_plans
for each row execute function public.audit_admin_row();
create trigger user_roles_audit_admin after insert or update or delete on public.user_roles
for each row execute function public.audit_admin_row();
create trigger admin_permissions_audit_admin after insert or update or delete on public.admin_permissions
for each row execute function public.audit_admin_row();
create trigger harassment_reports_audit_admin after update on public.harassment_reports
for each row execute function public.audit_admin_row();
create trigger moderation_actions_audit_admin after insert on public.moderation_actions
for each row execute function public.audit_admin_row();
create trigger deletion_reviews_audit_admin after insert or update on public.account_deletion_reviews
for each row execute function public.audit_admin_row();
create trigger profiles_audit_status after update of account_status on public.profiles
for each row execute function public.audit_profile_status();
create trigger reviews_audit_moderation after update of status on public.reviews
for each row execute function public.audit_admin_row();

alter table public.user_roles enable row level security;
alter table public.admin_permissions enable row level security;
alter table public.profiles enable row level security;
alter table public.memberships enable row level security;
alter table public.trial_claims enable row level security;
alter table public.membership_plans enable row level security;
alter table public.plan_price_history enable row level security;
alter table public.payments enable row level security;
alter table public.harassment_reports enable row level security;
alter table public.moderation_actions enable row level security;
alter table public.account_deletion_reviews enable row level security;
alter table public.audit_log enable row level security;
alter table public.reviews enable row level security;
alter table public.contact_messages enable row level security;

create policy "Staff can read roles" on public.user_roles for select to authenticated
using (public.has_permission('business.admins.manage'));
create policy "Owners assign staff roles" on public.user_roles for insert to authenticated
with check (
  public.has_permission('business.admins.manage')
  and user_id <> auth.uid()
  and role <> 'OWNER'
);
create policy "Owners update other staff roles" on public.user_roles for update to authenticated
using (public.has_permission('business.admins.manage') and user_id <> auth.uid())
with check (
  public.has_permission('business.admins.manage')
  and user_id <> auth.uid()
  and role <> 'OWNER'
);
create policy "Owners revoke other staff roles" on public.user_roles for delete to authenticated
using (public.has_permission('business.admins.manage') and user_id <> auth.uid());
create policy "Owners read assigned permissions" on public.admin_permissions for select to authenticated
using (public.has_permission('business.admins.manage'));
create policy "Owners grant permissions" on public.admin_permissions for insert to authenticated
with check (public.has_permission('business.admins.manage') and user_id <> auth.uid());
create policy "Owners revoke permissions" on public.admin_permissions for delete to authenticated
using (public.has_permission('business.admins.manage') and user_id <> auth.uid());

create policy "Members can see their own or discoverable active profiles" on public.profiles for select to authenticated
using (
  user_id = auth.uid()
  or public.has_permission('business.accounts.manage')
  or (
    public.has_permission('trust.reports.read')
    and exists (
      select 1 from public.harassment_reports report
      where report.reported_user_id = profiles.user_id and report.assigned_to = auth.uid()
    )
  )
);
create policy "Members update their own active profile" on public.profiles for update to authenticated
using (user_id = auth.uid() and account_status = 'active')
with check (user_id = auth.uid() and account_status = 'active');
create policy "Members read their own memberships" on public.memberships for select to authenticated
using (user_id = auth.uid() or public.has_permission('business.dashboard.read'));
create policy "Users read their trial eligibility record" on public.trial_claims for select to authenticated
using (user_id = auth.uid());

create policy "Enabled plans are public" on public.membership_plans for select to anon
using (enabled);
create policy "Authenticated members and staff read plans" on public.membership_plans for select to authenticated
using (enabled or public.has_permission('business.plans.manage'));
create policy "Owners manage plans" on public.membership_plans for all to authenticated
using (public.has_permission('business.plans.manage'))
with check (public.has_permission('business.plans.manage'));
create policy "Owners read plan price history" on public.plan_price_history for select to authenticated
using (public.has_permission('business.plans.manage'));
create policy "Owners read payments and members read own payments" on public.payments for select to authenticated
using (user_id = auth.uid() or public.has_permission('business.payments.read'));

create policy "Authorized staff read reports" on public.harassment_reports for select to authenticated
using (
  public.has_permission('business.admins.manage')
  or (
    public.has_permission('trust.reports.read')
    and (assigned_to is null or assigned_to = auth.uid())
  )
);
create policy "Authorized staff read moderation history" on public.moderation_actions for select to authenticated
using (public.has_permission('trust.reports.read'));
create policy "Authorized staff record moderation actions" on public.moderation_actions for insert to authenticated
with check (
  actor_id = auth.uid()
  and (public.has_permission('trust.accounts.manage') or public.has_permission('business.accounts.manage'))
);
create policy "Authorized staff read deletion reviews" on public.account_deletion_reviews for select to authenticated
using (public.has_permission('business.accounts.manage'));
create policy "Members request their own deletion review" on public.account_deletion_reviews for insert to authenticated
with check (requested_by = auth.uid() and user_id = auth.uid());
create policy "Authorized staff update deletion reviews" on public.account_deletion_reviews for update to authenticated
using (public.has_permission('business.accounts.manage'))
with check (public.has_permission('business.accounts.manage'));

create policy "Authorized staff read audit log" on public.audit_log for select to authenticated
using (public.has_permission('business.audit.read'));
create policy "Members read own reviews and staff read moderation queue" on public.reviews for select to authenticated
using (user_id = auth.uid() or public.has_permission('business.accounts.manage'));
create policy "Signed-in members can submit reviews" on public.reviews for insert to authenticated
with check (user_id = auth.uid() and status = 'pending');
create policy "Owners moderate reviews" on public.reviews for update to authenticated
using (public.has_permission('business.accounts.manage'))
with check (public.has_permission('business.accounts.manage'));
create policy "Owners read contact messages" on public.contact_messages for select to authenticated
using (public.has_permission('business.dashboard.read'));

grant select on public.profiles to authenticated;
grant update (display_name, birth_date, gender, marital_status, religion, caste, city, education, occupation, description, visibility)
  on public.profiles to authenticated;
grant select on public.memberships, public.trial_claims to authenticated;
grant select, insert, update, delete on public.user_roles, public.admin_permissions to authenticated;
grant select on public.membership_plans to anon;
grant select, insert, update, delete on public.membership_plans to authenticated;
grant select on public.plan_price_history, public.payments, public.harassment_reports,
  public.moderation_actions, public.account_deletion_reviews, public.audit_log to authenticated;
grant insert, update on public.account_deletion_reviews to authenticated;
grant update on public.reviews to authenticated;
grant select, insert on public.reviews to authenticated;
grant select on public.contact_messages to authenticated;
-- Configure this initial Owner manually in the Supabase SQL Editor after verifying
-- the intended user's auth.users.id. Never bootstrap from public registration.
-- insert into public.user_roles (user_id, role)
-- values ('REPLACE-WITH-VERIFIED-AUTH-USER-UUID', 'OWNER');
