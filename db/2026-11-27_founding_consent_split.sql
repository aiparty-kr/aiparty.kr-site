-- Additive follow-up to 2026-11-20_social_founding_consent.sql. Apply after the site
-- version that sends the split consents is deployed: from here on the database
-- rejects a founder submission unless each required consent is given separately.
--
-- Why: 발기인 참여 사실은 정치적 견해(개인정보 보호법 제23조 민감정보)라서 다른 동의와
-- 분리한 별도 동의가 필요하다. 정당법 제22조 자격 확인과 발기인 동의도 따로 받는다.
-- Rows submitted before this migration keep NULL in the new columns, which marks
-- them as collected under the earlier combined consent (consent_version NULL).
begin;

alter table public.founding_members
  add column if not exists founder_agreed boolean,
  add column if not exists eligibility_confirmed boolean,
  add column if not exists sensitive_agreed boolean,
  add column if not exists contact_consent boolean not null default false,
  add column if not exists consent_version text;

create or replace function private.community_validate_founder(p_founder jsonb)
returns jsonb language plpgsql stable security definer set search_path = ''
as $$
declare v_today date := (now() at time zone 'Asia/Seoul')::date;
  v_birth date; v_signature text; v_png bytea; v_mobile text; v_home text; v_field text; v_width bigint; v_height bigint;
begin
  if p_founder is null or jsonb_typeof(p_founder) <> 'object' or octet_length(p_founder::text) > 420000
    or p_founder -> 'privacy_agreed' is distinct from 'true'::jsonb
    or p_founder -> 'founder_agreed' is distinct from 'true'::jsonb
    or p_founder -> 'eligibility_confirmed' is distinct from 'true'::jsonb
    or p_founder -> 'sensitive_agreed' is distinct from 'true'::jsonb then
    raise exception 'COMMUNITY_FOUNDER_INVALID' using errcode = '22023';
  end if;
  foreach v_field in array array['name','address','birth_date','gender','occupation','phone_mobile','signature_data','agreed_at'] loop
    if jsonb_typeof(p_founder -> v_field) is distinct from 'string' then raise exception 'COMMUNITY_FOUNDER_INVALID' using errcode = '22023'; end if;
  end loop;
  if p_founder ? 'phone_home' and jsonb_typeof(p_founder -> 'phone_home') not in ('string','null') then
    raise exception 'COMMUNITY_FOUNDER_INVALID' using errcode = '22023';
  end if;
  if coalesce(char_length(btrim(p_founder ->> 'name')),0) not between 2 and 80
    or coalesce(char_length(btrim(p_founder ->> 'address')),0) not between 5 and 500
    or coalesce(char_length(btrim(p_founder ->> 'occupation')),0) not between 1 and 120
    or coalesce(p_founder ->> 'gender','') not in ('남','여') then
    raise exception 'COMMUNITY_FOUNDER_INVALID' using errcode = '22023';
  end if;
  if coalesce(p_founder ->> 'birth_date','') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' then
    raise exception 'COMMUNITY_FOUNDER_BIRTH_INVALID' using errcode = '22023';
  end if;
  begin v_birth := (p_founder ->> 'birth_date')::date;
  exception when others then raise exception 'COMMUNITY_FOUNDER_BIRTH_INVALID' using errcode = '22023'; end;
  if v_birth > (v_today - interval '18 years')::date then
    raise exception 'COMMUNITY_FOUNDER_AGE_REQUIRED' using errcode = '22023';
  end if;
  v_mobile := btrim(p_founder ->> 'phone_mobile');
  v_home := nullif(btrim(p_founder ->> 'phone_home'),'');
  if v_mobile is null or char_length(v_mobile) > 32
    or v_mobile !~ '^[0-9+()[:space:]-]+$'
    or regexp_replace(v_mobile,'[^0-9]','','g') !~ '^01[016789][0-9]{7,8}$'
    or (v_home is not null and (char_length(v_home) > 32 or v_home !~ '^[0-9+()[:space:]-]{6,32}$')) then
    raise exception 'COMMUNITY_FOUNDER_PHONE_INVALID' using errcode = '22023';
  end if;
  if (p_founder ? 'public_consent' and jsonb_typeof(p_founder -> 'public_consent') <> 'boolean')
    or (p_founder ? 'contact_consent' and jsonb_typeof(p_founder -> 'contact_consent') <> 'boolean') then
    raise exception 'COMMUNITY_FOUNDER_INVALID' using errcode = '22023';
  end if;
  if coalesce(p_founder ->> 'agreed_at','') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' then
    raise exception 'COMMUNITY_FOUNDER_DATE_INVALID' using errcode = '22023';
  end if;
  begin
    if abs((p_founder ->> 'agreed_at')::date - v_today) > 1 then
      raise exception 'COMMUNITY_FOUNDER_DATE_INVALID' using errcode = '22023';
    end if;
  exception when others then raise exception 'COMMUNITY_FOUNDER_DATE_INVALID' using errcode = '22023'; end;
  v_signature := p_founder ->> 'signature_data';
  if v_signature is null or char_length(v_signature) > 409622
    or v_signature !~ '^data:image/png;base64,[A-Za-z0-9+/]+={0,2}$' then
    raise exception 'COMMUNITY_FOUNDER_SIGNATURE_INVALID' using errcode = '22023';
  end if;
  begin v_png := decode(substr(v_signature,23),'base64');
  exception when others then raise exception 'COMMUNITY_FOUNDER_SIGNATURE_INVALID' using errcode = '22023'; end;
  if octet_length(v_png) not between 33 and 307200
    or substring(v_png from 1 for 8) <> decode('89504e470d0a1a0a','hex')
    or substring(v_png from 9 for 8) <> decode('0000000d49484452','hex')
    or substring(v_png from octet_length(v_png) - 11 for 12) <> decode('0000000049454e44ae426082','hex') then
    raise exception 'COMMUNITY_FOUNDER_SIGNATURE_INVALID' using errcode = '22023';
  end if;
  v_width := get_byte(v_png,16)::bigint * 16777216 + get_byte(v_png,17) * 65536 + get_byte(v_png,18) * 256 + get_byte(v_png,19);
  v_height := get_byte(v_png,20)::bigint * 16777216 + get_byte(v_png,21) * 65536 + get_byte(v_png,22) * 256 + get_byte(v_png,23);
  if v_width not between 1 and 4096 or v_height not between 1 and 4096 then
    raise exception 'COMMUNITY_FOUNDER_SIGNATURE_INVALID' using errcode = '22023';
  end if;
  -- Whitelist fields; discard caller-supplied ids, ownership, status and extras.
  return jsonb_build_object('name',btrim(p_founder ->> 'name'),'address',btrim(p_founder ->> 'address'),
    'birth_date',v_birth,'gender',p_founder ->> 'gender','occupation',btrim(p_founder ->> 'occupation'),
    'phone_home',v_home,'phone_mobile',v_mobile,'signature_data',v_signature,'agreed_at',v_today,
    'privacy_agreed',true,'public_consent',coalesce((p_founder ->> 'public_consent')::boolean,false),
    'founder_agreed',true,'eligibility_confirmed',true,'sensitive_agreed',true,
    'contact_consent',coalesce((p_founder ->> 'contact_consent')::boolean,false),'consent_version','2026-11-27');
end $$;
revoke all on function private.community_validate_founder(jsonb) from public,anon,authenticated;

create or replace function private.community_insert_founder(p_user uuid,p_founder jsonb)
returns uuid language plpgsql security definer set search_path = ''
as $$ declare v_id uuid; begin
  insert into public.founding_members(name,address,birth_date,gender,occupation,phone_home,phone_mobile,
    signature_data,agreed_at,privacy_agreed,public_consent,founder_agreed,eligibility_confirmed,sensitive_agreed,
    contact_consent,consent_version,submitted_by)
  values(p_founder ->> 'name',p_founder ->> 'address',(p_founder ->> 'birth_date')::date,p_founder ->> 'gender',
    p_founder ->> 'occupation',p_founder ->> 'phone_home',p_founder ->> 'phone_mobile',p_founder ->> 'signature_data',
    (p_founder ->> 'agreed_at')::date,true,(p_founder ->> 'public_consent')::boolean,
    true,true,true,(p_founder ->> 'contact_consent')::boolean,p_founder ->> 'consent_version',p_user) returning id into v_id;
  return v_id;
end $$;
revoke all on function private.community_insert_founder(uuid,jsonb) from public,anon,authenticated;

notify pgrst, 'reload schema';
commit;
