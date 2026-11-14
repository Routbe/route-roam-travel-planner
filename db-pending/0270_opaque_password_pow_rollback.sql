-- Rollback of 0270 (OPAQUE password sign-in + Hashcash PoW). Run only by the
-- owner, only after a separate GO, and only while nobody has set a password:
-- dropping pake_registrations would remove members' only copy of their record.
-- The OPAQUE server setup is dropped with it (no other key depends on it).
-- The audit log is append-only: when it already holds rows with the 0270
-- actions, the wider action check stays (narrowing it would fail on them).

do $$
begin
  if to_regclass('vault_enclave.pake_registrations') is not null
     and exists (select 1 from vault_enclave.pake_registrations) then
    raise exception '0270 rollback refused: password registrations exist';
  end if;
end $$;

drop function if exists vault_enclave.pake_login_denied(uuid);
drop function if exists vault_enclave.pake_login_granted(uuid);
drop function if exists vault_enclave.pake_login_claim(uuid);
drop function if exists vault_enclave.pake_login_begin(uuid, bytea, bytea);
drop function if exists vault_enclave.remove_pake_registration(uuid);
drop function if exists vault_enclave.store_pake_signup_registration(bytea, bytea, bytea, bytea);
drop function if exists vault_enclave.store_pake_registration(bytea, bytea, bytea, bytea, uuid);
drop function if exists vault_enclave.pake_registered(uuid);
drop function if exists vault_enclave.pake_registration_for_login(bytea);
drop function if exists vault_enclave.auth_pow_consume(uuid, bytea, text, bytea);
drop function if exists vault_enclave.auth_pow_issue(text, bytea);
drop function if exists vault_enclave.register_pake_setup(bytea, bytea);
drop function if exists vault_enclave.pake_setup_get(bytea);
drop function if exists vault_enclave.pake_setup_active();
drop function if exists vault_enclave.pake_recent_failures(bytea);
drop function if exists vault_enclave.pow_leading_zero_bits(bytea);

drop table if exists vault_enclave.pake_handshakes;
drop table if exists vault_enclave.auth_pow_challenges;
drop table if exists vault_enclave.pake_registrations;
-- The append-only guard refuses DELETE but not DROP; drop its triggers first for clarity.
drop trigger if exists pake_setups_guard on vault_enclave.pake_setups;
drop trigger if exists pake_setups_no_truncate on vault_enclave.pake_setups;
drop table if exists vault_enclave.pake_setups;
drop function if exists vault_enclave.pake_setups_guard();

do $$
begin
  if not exists (select 1 from vault_enclave.audit_logs a
                  where a.action in ('pake_setup_register', 'pake_register', 'pake_signup_register', 'pake_unregister', 'pake_login')) then
    alter table vault_enclave.audit_logs drop constraint audit_logs_action_check;
    alter table vault_enclave.audit_logs add constraint audit_logs_action_check
      check (action in ('step_up_register', 'token_store', 'token_retrieve', 'server_key_register',
                        'sdm_card_register', 'sdm_recovery_retrieve', 'sdm_recovery_confirm',
                        'sdm_fleet_register', 'sdm_batch_register', 'sdm_batch_cards_register',
                        'sdm_tap_begin', 'sdm_tap_confirm', 'sdm_tap_consume',
                        'sdm_card_activate', 'sdm_batch_list', 'sdm_batch_export',
                        'sdm_station_register', 'sdm_station_list', 'sdm_station_retire',
                        'card_step_up_begin', 'card_step_up_complete', 'card_step_up_claim',
                        'sdm_card_revoke'));
  else
    raise notice '0270 rollback: audit rows with 0270 actions exist; the wider audit action check stays';
  end if;
end $$;
