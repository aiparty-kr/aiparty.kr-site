-- Additive follow-up. Run in Supabase SQL Editor after the earlier founding files.
-- 종이 발기인 동의서를 운영자가 관리자 페이지에서 등록한다.
-- - 출처(source)를 'online' / 'paper' 로 구분한다. 기존 행은 모두 'online'.
-- - 종이 행은 서명 이미지 대신 원본 사진의 구글 드라이브 파일 ID(paper_ref)를 남긴다.
--   원본 종이는 결성신고 때 제출하므로 따로 보관한다.
-- - 온라인·종이 기존 발기인과 이름+생년월일 또는 휴대폰 번호가 같으면 등록하지 않고 알려 준다.
-- - 운영자(public.is_site_admin())만 호출할 수 있다.
begin;

alter table public.founding_members
  add column if not exists source text not null default 'online',
  add column if not exists paper_ref text,
  add column if not exists registered_by uuid references auth.users(id) on delete set null,
  add column if not exists paper_note text;

do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'founding_members_source_check') then
    alter table public.founding_members add constraint founding_members_source_check
      check (source in ('online','paper'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'founding_members_paper_ref_check') then
    alter table public.founding_members add constraint founding_members_paper_ref_check
      check (source <> 'paper' or (paper_ref is not null and paper_ref ~ '^[A-Za-z0-9_-]{10,200}(#p[0-9]{1,4})?$'));
  end if;
end $$;

-- 종이 행에는 서명 이미지가 없고, 종이 양식은 성별·휴대폰을 비워 두는 경우가 많다.
-- 온라인 행은 계속 셋 다 있어야 한다.
alter table public.founding_members alter column signature_data drop not null;
alter table public.founding_members alter column gender drop not null;
alter table public.founding_members alter column phone_mobile drop not null;
do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'founding_members_signature_by_source') then
    alter table public.founding_members add constraint founding_members_signature_by_source
      check (source = 'paper' or (signature_data is not null and gender is not null and phone_mobile is not null)) not valid;
  end if;
end $$;

-- 종이 행은 운영자 계정에 묶이지 않는다(submitted_by NULL). 그 밖의 동작은 그대로.
create or replace function private.community_legacy_owner()
returns trigger language plpgsql security definer set search_path = ''
as $$ begin
  if tg_op = 'INSERT' then
    if tg_table_name = 'founding_members' and (to_jsonb(new) ->> 'source') = 'paper' then
      new.submitted_by := null;
    else
      new.submitted_by := auth.uid();
    end if;
  else new.submitted_by := old.submitted_by;
  end if;
  return new;
end $$;
revoke all on function private.community_legacy_owner() from public, anon, authenticated;

-- p_rows: [{name, birth_date, gender, occupation, address, phone_mobile, phone_home,
--           agreed_at, signature(true), paper_ref}, ...]
-- 성별·휴대폰·자택전화는 비어 있어도 된다(적혀 있으면 형식을 검사한다).
-- 직업이 비면 '미기재'로 넣는다. note 는 글씨가 불분명한 칸 같은 확인할 거리로, paper_note 에 남는다.
-- paper_ref 는 드라이브 파일 ID, 여러 쪽짜리 스캔이면 '파일ID#p3' 처럼 쪽 번호를 붙인다.
-- p_commit=false 이면 검사만 한다. true 이면 status 'ok' 인 행만 넣는다.
create or replace function public.admin_import_paper_founders(p_rows jsonb, p_commit boolean default false)
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare
  v_today date := (now() at time zone 'Asia/Seoul')::date;
  v_out jsonb := '[]'::jsonb;
  v_row jsonb; v_i int := 0;
  v_name text; v_addr text; v_occ text; v_note text; v_gender text; v_mobile text; v_home text; v_ref text;
  v_birth date; v_agreed date; v_digits text;
  v_err text; v_match record; v_id uuid;
  v_seen text[] := '{}';
  v_key1 text; v_key2 text;
begin
  if not public.is_site_admin() then
    raise exception 'ADMIN_REQUIRED' using errcode = '42501';
  end if;
  if p_rows is null or jsonb_typeof(p_rows) <> 'array' or jsonb_array_length(p_rows) not between 1 and 300 then
    raise exception 'ROWS_INVALID' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended('paper-founder-import',7));

  for v_row in select value from jsonb_array_elements(p_rows) loop
    v_i := v_i + 1; v_err := null; v_birth := null; v_agreed := null; v_id := null;
    v_name := btrim(coalesce(v_row ->> 'name',''));
    v_addr := btrim(coalesce(v_row ->> 'address',''));
    v_occ := btrim(coalesce(v_row ->> 'occupation',''));
    v_gender := nullif(btrim(coalesce(v_row ->> 'gender','')),'');
    v_mobile := nullif(btrim(coalesce(v_row ->> 'phone_mobile','')),'');
    v_home := nullif(btrim(coalesce(v_row ->> 'phone_home','')),'');
    v_ref := btrim(coalesce(v_row ->> 'paper_ref',''));
    v_note := nullif(left(btrim(coalesce(v_row ->> 'note','')),500),'');
    if v_occ = '' then v_occ := '미기재'; end if;
    v_digits := regexp_replace(coalesce(v_mobile,''),'[^0-9]','','g');

    begin v_birth := (v_row ->> 'birth_date')::date; exception when others then v_birth := null; end;
    begin v_agreed := (v_row ->> 'agreed_at')::date; exception when others then v_agreed := null; end;

    if jsonb_typeof(v_row) <> 'object' then v_err := '형식 오류';
    elsif char_length(v_name) not between 2 and 80 then v_err := '이름';
    elsif v_birth is null then v_err := '생년월일';
    elsif v_gender is not null and v_gender not in ('남','여') then v_err := '성별(남/여)';
    elsif char_length(v_occ) not between 1 and 120 then v_err := '직업';
    elsif char_length(v_addr) not between 2 and 500 then v_err := '주소';
    elsif v_mobile is not null and (v_digits !~ '^01[016789][0-9]{7,8}$' or char_length(v_mobile) > 32) then v_err := '휴대폰';
    elsif v_home is not null and (char_length(v_home) > 32 or v_home !~ '^[0-9+()[:space:]-]{6,32}$') then v_err := '자택전화';
    elsif v_agreed is null or v_agreed > v_today then v_err := '작성일';
    elsif v_birth > (v_agreed - interval '18 years')::date then v_err := '작성일 기준 만 18세 미만';
    elsif v_row -> 'signature' is distinct from 'true'::jsonb then v_err := '서명 없음';
    elsif v_ref !~ '^[A-Za-z0-9_-]{10,200}(#p[0-9]{1,4})?$' then v_err := '사진ID';
    end if;

    if v_err is not null then
      v_out := v_out || jsonb_build_object('row',v_i,'name',v_name,'status','invalid','reason',v_err);
      continue;
    end if;

    select m.id, m.name, m.source, m.created_at into v_match
      from public.founding_members m
      where (m.name = v_name and m.birth_date = v_birth)
         or (v_digits <> '' and regexp_replace(coalesce(m.phone_mobile,''),'[^0-9]','','g') = v_digits)
      order by m.created_at limit 1;
    if found then
      v_out := v_out || jsonb_build_object('row',v_i,'name',v_name,'status','duplicate',
        'reason', case when v_match.source = 'paper' then '이미 종이로 등록됨' else '온라인 가입자와 중복' end,
        'match_name', v_match.name, 'match_source', v_match.source);
      continue;
    end if;

    v_key1 := v_name || '|' || v_birth::text; v_key2 := case when v_digits <> '' then 'p|' || v_digits end;
    if v_key1 = any(v_seen) or (v_key2 is not null and v_key2 = any(v_seen)) then
      v_out := v_out || jsonb_build_object('row',v_i,'name',v_name,'status','duplicate','reason','붙여넣은 목록 안에서 중복');
      continue;
    end if;
    v_seen := v_seen || v_key1;
    if v_key2 is not null then v_seen := v_seen || v_key2; end if;

    if p_commit then
      insert into public.founding_members(name,address,birth_date,gender,occupation,phone_home,phone_mobile,
        signature_data,agreed_at,privacy_agreed,public_consent,source,paper_ref,registered_by,paper_note)
      values(v_name,v_addr,v_birth,v_gender,v_occ,v_home,v_mobile,null,v_agreed,true,false,'paper',v_ref,auth.uid(),v_note)
      returning id into v_id;
      v_out := v_out || jsonb_build_object('row',v_i,'name',v_name,'status','registered','id',v_id);
    else
      v_out := v_out || jsonb_build_object('row',v_i,'name',v_name,'status','ok');
    end if;
  end loop;
  return v_out;
end $$;
revoke all on function public.admin_import_paper_founders(jsonb,boolean) from public, anon;
grant execute on function public.admin_import_paper_founders(jsonb,boolean) to authenticated;

notify pgrst, 'reload schema';
commit;
