-- 0270 — Password sign-in without the password ever reaching the server
-- (OPAQUE, RFC 9807) and Hashcash proof-of-work before every handshake (Stap 3).
-- EXPAND only: new tables in vault_enclave (deny-all, no rights for rout_app)
-- and SECURITY DEFINER entry points; nothing existing changes except a wider
-- audit action check. Held in db-pending/ until the owner's GO.
--
--   pake_setups          the OPAQUE server setup (OPRF seed + AKE key pair) only
--                        as an RVE1 envelope (kind opk = 7, holder server vault)
--                        sealed to a vault_enclave.server_keys key, whose seed is
--                        wrapped under the Master KEK (db/0222). A dump of this
--                        database alone cannot evaluate the OPRF, so it cannot
--                        run a dictionary attack on any registration record.
--   pake_registrations   one OPAQUE record (192 bytes: client public key,
--                        masking key, envelope) per Better Auth user, found by a
--                        keyed digest of the e-mail (HMAC under a key derived
--                        from the setup), never by the e-mail itself.
--   auth_pow_challenges  one-time Hashcash challenges, 120 s on the database
--                        clock, difficulty rising with failed handshakes for the
--                        same digest and with global load. Verified here:
--                        SHA-256("rout.pow.v1" || challenge || nonce) must start
--                        with `bits` zero bits; every attempt burns the challenge.
--   pake_handshakes      the server's KE2 state between the two login requests,
--                        sealed by the app (XChaCha20-Poly1305 under a key derived
--                        from the setup), 60 s, claimed once.
--
-- Every step is one self-contained transaction (FOR UPDATE on the row it
-- changes, no session variables, advisory locks only inside the audit append
-- as before): safe on pooled Neon HTTP connections. Denials return false or no
-- row instead of raising, so their audit rows commit.

alter table vault_enclave.audit_logs drop constraint audit_logs_action_check;
alter table vault_enclave.audit_logs add constraint audit_logs_action_check
  check (action in ('step_up_register', 'token_store', 'token_retrieve', 'server_key_register',
                    'sdm_card_register', 'sdm_recovery_retrieve', 'sdm_recovery_confirm',
                    'sdm_fleet_register', 'sdm_batch_register', 'sdm_batch_cards_register',
                    'sdm_tap_begin', 'sdm_tap_confirm', 'sdm_tap_consume',
                    'sdm_card_activate', 'sdm_batch_list', 'sdm_batch_export',
                    'sdm_station_register', 'sdm_station_list', 'sdm_station_retire',
                    'card_step_up_begin', 'card_step_up_complete', 'card_step_up_claim',
                    'sdm_card_revoke',
                    'pake_setup_register', 'pake_register', 'pake_signup_register',
                    'pake_unregister', 'pake_login'));

-- ---------------------------------------------------------------- tables

create table vault_enclave.pake_setups (
  kid bytea primary key,
  envelope bytea not null,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  retired_at timestamptz,
  constraint pake_setups_kid_matches check (
    kid = substring(pg_catalog.sha256(pg_catalog.convert_to('rout.pake.setup-kid', 'UTF8') || envelope) from 1 for 16)),
  -- RVE1 header: magic, suite 1, kind opk (7), holder server vault (1); 128-byte setup + overhead.
  constraint pake_setups_envelope_header check (
    substring(envelope from 1 for 4) = '\x52564531'::bytea
    and pg_catalog.get_byte(envelope, 4) = 1
    and pg_catalog.get_byte(envelope, 5) = 7
    and pg_catalog.get_byte(envelope, 6) = 1),
  constraint pake_setups_envelope_len check (octet_length(envelope) between 1664 and 2304)
);
create unique index pake_setups_one_active on vault_enclave.pake_setups ((true)) where retired_at is null;

create table vault_enclave.pake_registrations (
  auth_user_id uuid primary key references neon_auth."user"(id) on delete cascade,
  lookup_digest bytea not null unique,
  credential_id bytea not null unique,
  record bytea not null,
  setup_kid bytea not null references vault_enclave.pake_setups(kid),
  version integer not null default 1,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  updated_at timestamptz not null default pg_catalog.clock_timestamp(),
  constraint pake_registrations_lookup_len check (octet_length(lookup_digest) = 32),
  constraint pake_registrations_credential_len check (octet_length(credential_id) = 32),
  constraint pake_registrations_record_len check (octet_length(record) = 192),
  constraint pake_registrations_version check (version >= 1)
);

create table vault_enclave.auth_pow_challenges (
  id uuid primary key default pg_catalog.gen_random_uuid(),
  challenge bytea not null,
  purpose text not null,
  scope_digest bytea not null,
  bits smallint not null,
  issued_at timestamptz not null,
  expires_at timestamptz not null,
  spent_at timestamptz,
  constraint auth_pow_challenge_len check (octet_length(challenge) = 32),
  constraint auth_pow_scope_len check (octet_length(scope_digest) = 32),
  constraint auth_pow_purpose check (purpose in ('opaque_login', 'opaque_signup', 'opaque_register')),
  constraint auth_pow_bits check (bits between 16 and 26),
  constraint auth_pow_ttl check (expires_at > issued_at and expires_at <= issued_at + interval '120 seconds')
);
create index auth_pow_scope_idx on vault_enclave.auth_pow_challenges (scope_digest, issued_at);
create index auth_pow_issued_idx on vault_enclave.auth_pow_challenges (issued_at);

create table vault_enclave.pake_handshakes (
  id uuid primary key,
  lookup_digest bytea not null,
  state_sealed bytea not null,
  created_at timestamptz not null,
  expires_at timestamptz not null,
  claimed_at timestamptz,
  outcome text,
  constraint pake_handshakes_lookup_len check (octet_length(lookup_digest) = 32),
  constraint pake_handshakes_state_len check (octet_length(state_sealed) between 41 and 600),
  constraint pake_handshakes_ttl check (expires_at > created_at and expires_at <= created_at + interval '60 seconds'),
  constraint pake_handshakes_outcome check (outcome in ('granted', 'denied'))
);
create index pake_handshakes_lookup_idx on vault_enclave.pake_handshakes (lookup_digest, created_at);
create index pake_handshakes_created_idx on vault_enclave.pake_handshakes (created_at);

revoke all on table vault_enclave.pake_setups, vault_enclave.pake_registrations,
                    vault_enclave.auth_pow_challenges, vault_enclave.pake_handshakes from public, rout_app;
alter table vault_enclave.pake_setups enable row level security;
alter table vault_enclave.pake_registrations enable row level security;
alter table vault_enclave.auth_pow_challenges enable row level security;
alter table vault_enclave.pake_handshakes enable row level security;

-- Setups are never deleted and never change, except being retired once.
create function vault_enclave.pake_setups_guard() returns trigger
language plpgsql set search_path = pg_catalog, pg_temp as $$
begin
  if tg_op = 'DELETE' then raise exception 'vault_enclave.pake_setups is append-only'; end if;
  if old.retired_at is not null or new.retired_at is null
     or (new.kid, new.envelope, new.created_at) is distinct from (old.kid, old.envelope, old.created_at) then
    raise exception 'vault_enclave.pake_setups rows can only be retired once';
  end if;
  return new;
end $$;
create trigger pake_setups_guard before update or delete on vault_enclave.pake_setups
  for each row execute function vault_enclave.pake_setups_guard();
create trigger pake_setups_no_truncate before truncate on vault_enclave.pake_setups
  for each statement execute function vault_enclave.audit_logs_immutable();
revoke all on function vault_enclave.pake_setups_guard() from public, rout_app;

-- ---------------------------------------------------------------- helpers (owner only)

create function vault_enclave.pow_leading_zero_bits(p bytea) returns integer
language plpgsql immutable strict set search_path = pg_catalog, pg_temp as $$
declare
  i integer;
  b integer;
  n integer := 0;
begin
  for i in 0 .. pg_catalog.octet_length(p) - 1 loop
    b := pg_catalog.get_byte(p, i);
    if b = 0 then n := n + 8; continue; end if;
    while b < 128 loop b := b * 2; n := n + 1; end loop;
    return n;
  end loop;
  return n;
end $$;
revoke all on function vault_enclave.pow_leading_zero_bits(bytea) from public, rout_app;

-- Failed or abandoned handshakes for one digest in the last 15 minutes.
create function vault_enclave.pake_recent_failures(p_lookup bytea) returns integer
language sql stable set search_path = pg_catalog, pg_temp as $$
  select pg_catalog.count(*)::integer from vault_enclave.pake_handshakes h
   where h.lookup_digest = p_lookup
     and h.created_at > pg_catalog.clock_timestamp() - interval '15 minutes'
     and h.outcome is distinct from 'granted'
     and (h.outcome = 'denied' or h.expires_at < pg_catalog.clock_timestamp())
$$;
revoke all on function vault_enclave.pake_recent_failures(bytea) from public, rout_app;

-- ---------------------------------------------------------------- setup

create function vault_enclave.pake_setup_active()
returns table (kid bytea, envelope bytea)
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select s.kid, s.envelope from vault_enclave.pake_setups s where s.retired_at is null
$$;

create function vault_enclave.pake_setup_get(p_kid bytea)
returns table (kid bytea, envelope bytea)
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select s.kid, s.envelope from vault_enclave.pake_setups s where s.kid = p_kid
$$;

-- First writer wins; the envelope must be sealed to the active server key
-- (RVE1 recipient key id = bytes 8..23). Rotation is an owner operation.
create function vault_enclave.register_pake_setup(p_kid bytea, p_envelope bytea)
returns boolean language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v_rows integer;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'pake_setup_register', 'denied', 'no_caller', null); return false;
  end if;
  if p_envelope is null or octet_length(p_envelope) < 1664 or not exists (
       select 1 from vault_enclave.server_keys k
        where k.retired_at is null and k.kid = substring(p_envelope from 8 for 16)) then
    perform vault_enclave.append_audit(v_caller, 'pake_setup_register', 'denied', 'not_sealed_to_active_key', null); return false;
  end if;
  begin
    insert into vault_enclave.pake_setups (kid, envelope) values (p_kid, p_envelope) on conflict do nothing;
    get diagnostics v_rows = row_count;
  exception when check_violation then
    perform vault_enclave.append_audit(v_caller, 'pake_setup_register', 'denied', 'malformed', null); return false;
  end;
  if v_rows = 0 then
    perform vault_enclave.append_audit(v_caller, 'pake_setup_register', 'denied', 'already_active', null); return false;
  end if;
  perform vault_enclave.append_audit(v_caller, 'pake_setup_register', 'granted', 'ok', null);
  return true;
end $$;

-- ---------------------------------------------------------------- proof-of-work

create function vault_enclave.auth_pow_issue(p_purpose text, p_scope_digest bytea)
returns table (id uuid, challenge bytea, bits integer, expires_at timestamptz)
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_fail integer;
  v_scope integer;
  v_global integer;
  v_bits integer;
  v_id uuid;
  v_challenge bytea := public.gen_random_bytes(32);
begin
  if p_purpose not in ('opaque_login', 'opaque_signup', 'opaque_register')
     or p_scope_digest is null or octet_length(p_scope_digest) <> 32 then
    return;
  end if;
  -- Keep both tables small; bounded per call.
  delete from vault_enclave.auth_pow_challenges c
   where c.ctid in (select c2.ctid from vault_enclave.auth_pow_challenges c2
                     where c2.expires_at < v_now - interval '1 hour' limit 500);
  delete from vault_enclave.pake_handshakes h
   where h.ctid in (select h2.ctid from vault_enclave.pake_handshakes h2
                     where h2.created_at < v_now - interval '1 hour' limit 500);
  v_fail := vault_enclave.pake_recent_failures(p_scope_digest);
  select pg_catalog.count(*)::integer into v_scope from vault_enclave.auth_pow_challenges c
   where c.scope_digest = p_scope_digest and c.issued_at > v_now - interval '15 minutes';
  select pg_catalog.count(*)::integer into v_global from vault_enclave.auth_pow_challenges c
   where c.issued_at > v_now - interval '60 seconds';
  -- Nobody is blocked: work only gets more expensive (about 65 thousand to 67 million hashes).
  v_bits := least(26, 16 + least(v_fail, 6)
              + case when v_scope > 20 then 2 when v_scope > 5 then 1 else 0 end
              + case when v_global > 600 then 2 when v_global > 120 then 1 else 0 end);
  insert into vault_enclave.auth_pow_challenges (challenge, purpose, scope_digest, bits, issued_at, expires_at)
  values (v_challenge, p_purpose, p_scope_digest, v_bits, v_now, v_now + interval '120 seconds')
  returning auth_pow_challenges.id into v_id;
  return query select v_id, v_challenge, v_bits, v_now + interval '120 seconds';
end $$;

-- true once per challenge: right purpose and scope, not expired on the database
-- clock, and the work verifies. Any attempt spends the challenge.
create function vault_enclave.auth_pow_consume(p_id uuid, p_nonce bytea, p_purpose text, p_scope_digest bytea)
returns boolean language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_row vault_enclave.auth_pow_challenges%rowtype;
begin
  select * into v_row from vault_enclave.auth_pow_challenges c where c.id = p_id for update;
  if not found or v_row.spent_at is not null then return false; end if;
  update vault_enclave.auth_pow_challenges set spent_at = v_now where auth_pow_challenges.id = p_id;
  if v_row.expires_at < v_now or v_row.purpose is distinct from p_purpose
     or v_row.scope_digest is distinct from p_scope_digest
     or p_nonce is null or octet_length(p_nonce) <> 8 then
    return false;
  end if;
  return vault_enclave.pow_leading_zero_bits(
    pg_catalog.sha256(pg_catalog.convert_to('rout.pow.v1', 'UTF8') || v_row.challenge || p_nonce)) >= v_row.bits;
end $$;

-- ---------------------------------------------------------------- registrations

-- Anonymous: the login path needs the record (or nothing, for the RFC 9807 fake record).
create function vault_enclave.pake_registration_for_login(p_lookup bytea)
returns table (credential_id bytea, record bytea, setup_kid bytea)
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select r.credential_id, r.record, r.setup_kid from vault_enclave.pake_registrations r where r.lookup_digest = p_lookup
$$;

-- Whether a Better Auth identity has an OPAQUE password (member bridge, sign-in options).
create function vault_enclave.pake_registered(p_auth_user_id uuid)
returns boolean language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select exists (select 1 from vault_enclave.pake_registrations r where r.auth_user_id = p_auth_user_id)
$$;

-- Signed-in member sets or replaces their password. Needs a passkey step-up proof
-- registered on the database clock (db/0221), unused and at most 300 s old; it is spent here.
create function vault_enclave.store_pake_registration(
  p_lookup bytea, p_credential_id bytea, p_record bytea, p_setup_kid bytea, p_step_up_proof_id uuid)
returns boolean language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_auth uuid;
  v_proof vault_enclave.step_up_proofs%rowtype;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'pake_register', 'denied', 'no_caller', null); return false;
  end if;
  select u.auth_user_id into v_auth from public.users u where u.id = v_caller;
  if v_auth is null or not exists (select 1 from neon_auth."user" au where au.id = v_auth) then
    perform vault_enclave.append_audit(v_caller, 'pake_register', 'denied', 'no_identity', null); return false;
  end if;
  select * into v_proof from vault_enclave.step_up_proofs s
   where s.proof_id = p_step_up_proof_id and s.user_id = v_caller for update;
  if not found or v_proof.consumed_at is not null or v_proof.method <> 'passkey'
     or v_now - v_proof.verified_at > interval '300 seconds' or v_proof.verified_at > v_now + interval '5 seconds' then
    perform vault_enclave.append_audit(v_caller, 'pake_register', 'denied', 'step_up_missing', null); return false;
  end if;
  update vault_enclave.step_up_proofs set consumed_at = v_now where proof_id = v_proof.proof_id;
  if not exists (select 1 from vault_enclave.pake_setups s where s.kid = p_setup_kid and s.retired_at is null) then
    perform vault_enclave.append_audit(v_caller, 'pake_register', 'denied', 'setup_not_active', null); return false;
  end if;
  begin
    insert into vault_enclave.pake_registrations as r (auth_user_id, lookup_digest, credential_id, record, setup_kid)
    values (v_auth, p_lookup, p_credential_id, p_record, p_setup_kid)
    on conflict (auth_user_id) do update
      set lookup_digest = excluded.lookup_digest, credential_id = excluded.credential_id,
          record = excluded.record, setup_kid = excluded.setup_kid,
          version = r.version + 1, updated_at = v_now;
  exception when check_violation or unique_violation then
    perform vault_enclave.append_audit(v_caller, 'pake_register', 'denied', 'malformed_or_taken', null); return false;
  end;
  perform vault_enclave.append_audit(v_caller, 'pake_register', 'granted', 'ok', null);
  return true;
end $$;

-- New account by password (sign-up ticket verified by the app): only for a Better
-- Auth identity created in the last 15 minutes that has no passkey, no member row
-- and no password yet. The caller context is that identity.
create function vault_enclave.store_pake_signup_registration(
  p_lookup bytea, p_credential_id bytea, p_record bytea, p_setup_kid bytea)
returns boolean language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v_created timestamptz;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'pake_signup_register', 'denied', 'no_caller', null); return false;
  end if;
  select au."createdAt" into v_created from neon_auth."user" au where au.id = v_caller for update;
  if v_created is null or v_created < pg_catalog.clock_timestamp() - interval '15 minutes'
     or exists (select 1 from neon_auth.passkey k where k."userId" = v_caller::text)
     or exists (select 1 from public.users u where u.auth_user_id = v_caller or u.id = v_caller)
     or exists (select 1 from vault_enclave.pake_registrations r where r.auth_user_id = v_caller) then
    perform vault_enclave.append_audit(v_caller, 'pake_signup_register', 'denied', 'not_a_fresh_identity', null); return false;
  end if;
  if not exists (select 1 from vault_enclave.pake_setups s where s.kid = p_setup_kid and s.retired_at is null) then
    perform vault_enclave.append_audit(v_caller, 'pake_signup_register', 'denied', 'setup_not_active', null); return false;
  end if;
  begin
    insert into vault_enclave.pake_registrations (auth_user_id, lookup_digest, credential_id, record, setup_kid)
    values (v_caller, p_lookup, p_credential_id, p_record, p_setup_kid);
  exception when check_violation or unique_violation then
    perform vault_enclave.append_audit(v_caller, 'pake_signup_register', 'denied', 'malformed_or_taken', null); return false;
  end;
  perform vault_enclave.append_audit(v_caller, 'pake_signup_register', 'granted', 'ok', null);
  return true;
end $$;

-- Removes the caller's password, with a fresh passkey proof; never the last way in.
create function vault_enclave.remove_pake_registration(p_step_up_proof_id uuid)
returns boolean language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_auth uuid;
  v_rows integer;
  v_proof vault_enclave.step_up_proofs%rowtype;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'pake_unregister', 'denied', 'no_caller', null); return false;
  end if;
  select u.auth_user_id into v_auth from public.users u where u.id = v_caller;
  select * into v_proof from vault_enclave.step_up_proofs s
   where s.proof_id = p_step_up_proof_id and s.user_id = v_caller for update;
  if not found or v_proof.consumed_at is not null or v_proof.method <> 'passkey'
     or v_now - v_proof.verified_at > interval '300 seconds' or v_proof.verified_at > v_now + interval '5 seconds' then
    perform vault_enclave.append_audit(v_caller, 'pake_unregister', 'denied', 'step_up_missing', null); return false;
  end if;
  update vault_enclave.step_up_proofs set consumed_at = v_now where proof_id = v_proof.proof_id;
  if v_auth is null or not exists (select 1 from neon_auth.passkey k where k."userId" = v_auth::text) then
    perform vault_enclave.append_audit(v_caller, 'pake_unregister', 'denied', 'last_sign_in_method', null); return false;
  end if;
  delete from vault_enclave.pake_registrations r where r.auth_user_id = v_auth;
  get diagnostics v_rows = row_count;
  perform vault_enclave.append_audit(v_caller, 'pake_unregister', case when v_rows > 0 then 'granted' else 'denied' end,
                                     case when v_rows > 0 then 'ok' else 'none' end, null);
  return v_rows > 0;
end $$;

-- ---------------------------------------------------------------- login handshakes

-- Stores the sealed KE2 state for 60 s; at most 5 open handshakes per digest.
create function vault_enclave.pake_login_begin(p_id uuid, p_lookup bytea, p_state_sealed bytea)
returns boolean language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_rows integer;
begin
  if p_id is null or p_lookup is null or octet_length(p_lookup) <> 32 then return false; end if;
  if (select pg_catalog.count(*) from vault_enclave.pake_handshakes h
       where h.lookup_digest = p_lookup and h.claimed_at is null and h.expires_at > v_now) >= 5 then
    return false;
  end if;
  insert into vault_enclave.pake_handshakes (id, lookup_digest, state_sealed, created_at, expires_at)
  values (p_id, p_lookup, p_state_sealed, v_now, v_now + interval '60 seconds')
  on conflict do nothing;
  get diagnostics v_rows = row_count;
  return v_rows = 1;
exception when check_violation then
  return false;
end $$;

-- Claims a handshake once (outcome 'denied' until pake_login_granted flips it).
create function vault_enclave.pake_login_claim(p_id uuid)
returns table (lookup_digest bytea, state_sealed bytea)
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_row vault_enclave.pake_handshakes%rowtype;
begin
  select * into v_row from vault_enclave.pake_handshakes h where h.id = p_id for update;
  if not found or v_row.claimed_at is not null then return; end if;
  update vault_enclave.pake_handshakes set claimed_at = v_now, outcome = 'denied' where pake_handshakes.id = p_id;
  if v_row.expires_at < v_now then return; end if;
  return query select v_row.lookup_digest, v_row.state_sealed;
end $$;

-- After the app verified KE3: marks the claimed handshake granted (within 30 s of
-- the claim) and returns the Better Auth identity of the registration, or null.
create function vault_enclave.pake_login_granted(p_id uuid)
returns uuid language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_row vault_enclave.pake_handshakes%rowtype;
  v_auth uuid;
begin
  select * into v_row from vault_enclave.pake_handshakes h where h.id = p_id for update;
  if not found or v_row.claimed_at is null or v_row.outcome is distinct from 'denied'
     or v_now - v_row.claimed_at > interval '30 seconds' then
    return null;
  end if;
  select r.auth_user_id into v_auth from vault_enclave.pake_registrations r where r.lookup_digest = v_row.lookup_digest;
  if v_auth is null then
    perform vault_enclave.append_audit(null, 'pake_login', 'denied', 'no_registration', null); return null;
  end if;
  update vault_enclave.pake_handshakes set outcome = 'granted' where pake_handshakes.id = p_id;
  perform vault_enclave.append_audit(v_auth, 'pake_login', 'granted', 'ok', null);
  return v_auth;
end $$;

-- Records a verified failure on the audit chain (the claim already counted it).
create function vault_enclave.pake_login_denied(p_id uuid)
returns void language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
begin
  if exists (select 1 from vault_enclave.pake_handshakes h where h.id = p_id and h.outcome = 'denied') then
    perform vault_enclave.append_audit(null, 'pake_login', 'denied', 'bad_proof', null);
  end if;
end $$;

-- ---------------------------------------------------------------- rights

revoke all on function vault_enclave.pake_setup_active() from public;
revoke all on function vault_enclave.pake_setup_get(bytea) from public;
revoke all on function vault_enclave.register_pake_setup(bytea, bytea) from public;
revoke all on function vault_enclave.auth_pow_issue(text, bytea) from public;
revoke all on function vault_enclave.auth_pow_consume(uuid, bytea, text, bytea) from public;
revoke all on function vault_enclave.pake_registration_for_login(bytea) from public;
revoke all on function vault_enclave.pake_registered(uuid) from public;
revoke all on function vault_enclave.store_pake_registration(bytea, bytea, bytea, bytea, uuid) from public;
revoke all on function vault_enclave.store_pake_signup_registration(bytea, bytea, bytea, bytea) from public;
revoke all on function vault_enclave.remove_pake_registration(uuid) from public;
revoke all on function vault_enclave.pake_login_begin(uuid, bytea, bytea) from public;
revoke all on function vault_enclave.pake_login_claim(uuid) from public;
revoke all on function vault_enclave.pake_login_granted(uuid) from public;
revoke all on function vault_enclave.pake_login_denied(uuid) from public;
revoke all on function vault_enclave.pake_recent_failures(bytea) from public, rout_app;

grant execute on function vault_enclave.pake_setup_active() to rout_app;
grant execute on function vault_enclave.pake_setup_get(bytea) to rout_app;
grant execute on function vault_enclave.register_pake_setup(bytea, bytea) to rout_app;
grant execute on function vault_enclave.auth_pow_issue(text, bytea) to rout_app;
grant execute on function vault_enclave.auth_pow_consume(uuid, bytea, text, bytea) to rout_app;
grant execute on function vault_enclave.pake_registration_for_login(bytea) to rout_app;
grant execute on function vault_enclave.pake_registered(uuid) to rout_app;
grant execute on function vault_enclave.store_pake_registration(bytea, bytea, bytea, bytea, uuid) to rout_app;
grant execute on function vault_enclave.store_pake_signup_registration(bytea, bytea, bytea, bytea) to rout_app;
grant execute on function vault_enclave.remove_pake_registration(uuid) to rout_app;
grant execute on function vault_enclave.pake_login_begin(uuid, bytea, bytea) to rout_app;
grant execute on function vault_enclave.pake_login_claim(uuid) to rout_app;
grant execute on function vault_enclave.pake_login_granted(uuid) to rout_app;
grant execute on function vault_enclave.pake_login_denied(uuid) to rout_app;

-- In-transaction checks: rout_app reaches none of the new tables, every new
-- definer is pinned, PUBLIC executes none of them.
do $$
declare v_bad text;
begin
  select string_agg(c.relname, ', ') into v_bad from pg_catalog.pg_class c
   join pg_catalog.pg_namespace n on n.oid = c.relnamespace
   where n.nspname = 'vault_enclave' and c.relname in ('pake_setups', 'pake_registrations', 'auth_pow_challenges', 'pake_handshakes')
     and (pg_catalog.has_table_privilege('rout_app', c.oid, 'select') or pg_catalog.has_table_privilege('rout_app', c.oid, 'insert')
       or pg_catalog.has_table_privilege('rout_app', c.oid, 'update') or pg_catalog.has_table_privilege('rout_app', c.oid, 'delete')
       or not c.relrowsecurity);
  if v_bad is not null then raise exception '0270: rout_app can reach %', v_bad; end if;
  select string_agg(p.proname, ', ') into v_bad from pg_catalog.pg_proc p
   join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'vault_enclave' and p.prosecdef
     and (p.proname like 'pake\_%' or p.proname like 'auth\_pow\_%' or p.proname in ('register_pake_setup', 'store_pake_registration', 'store_pake_signup_registration', 'remove_pake_registration'))
     and (p.proconfig is null or not ('search_path=pg_catalog, pg_temp' = any (p.proconfig))
       or pg_catalog.has_function_privilege('public', p.oid, 'execute'));
  if v_bad is not null then raise exception '0270: unpinned or public definer %', v_bad; end if;
end $$;
