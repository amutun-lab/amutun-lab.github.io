-- ============================================================
-- 아무튼 열심히 연구소 · Supabase 설정 SQL
-- Supabase 대시보드 → SQL Editor → New query 에 전체를 붙여넣고 Run.
-- 여러 번 실행해도 안전합니다 (기존 글은 지워지지 않습니다).
-- ============================================================

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;
create schema if not exists private;          -- 외부(API)에 노출되지 않는 내부 함수용

-- ---------- 테이블 ----------
create table if not exists public.members (
  id          bigint generated always as identity primary key,
  login_id    text not null unique check (login_id ~ '^[a-z0-9_]{4,16}$'),
  nick        text not null unique check (char_length(nick) between 2 and 12),
  pw_hash     text not null,
  is_admin    boolean not null default false,
  created_at  timestamptz not null default now()
);

create table if not exists public.sessions (
  token       text primary key,
  member_id   bigint not null references public.members(id) on delete cascade,
  created_at  timestamptz not null default now(),
  expires_at  timestamptz not null default now() + interval '30 days'
);

create table if not exists public.posts (
  id          bigint generated always as identity primary key,
  board       text not null check (board in ('free','notice')),
  tag         text check (tag is null or char_length(tag) <= 10),
  title       text not null check (char_length(title) between 1 and 60),
  body        text not null check (char_length(body) between 1 and 5000),
  nick        text not null,
  member_id   bigint references public.members(id) on delete set null,
  pw_hash     text,
  ip_prefix   text,
  views       integer not null default 0,
  created_at  timestamptz not null default now()
);
create index if not exists posts_board_created on public.posts (board, created_at desc);

create table if not exists public.comments (
  id          bigint generated always as identity primary key,
  post_ref    text not null check (post_ref ~ '^(p[0-9]+|ai:[A-Za-z0-9_-]{1,40})$'),  -- p123 = 회원/비회원 글, ai:xxx = AI 글
  body        text not null check (char_length(body) between 1 and 500),
  nick        text not null,
  member_id   bigint references public.members(id) on delete set null,
  pw_hash     text,
  ip_prefix   text,
  created_at  timestamptz not null default now()
);
create index if not exists comments_ref on public.comments (post_ref, created_at);

create table if not exists public.scores (
  id          bigint generated always as identity primary key,
  game        text not null check (game in ('runner','whack','slack')),
  score       integer not null check (score >= 0),
  nick        text not null,
  member_id   bigint references public.members(id) on delete set null,
  created_at  timestamptz not null default now()
);
create index if not exists scores_game on public.scores (game, score desc);

-- 테이블은 API로 직접 읽고 쓸 수 없게 잠급니다. 읽기는 아래 뷰, 쓰기는 아래 함수로만.
alter table public.members  enable row level security;
alter table public.sessions enable row level security;
alter table public.posts    enable row level security;
alter table public.comments enable row level security;
alter table public.scores   enable row level security;
revoke all on public.members, public.sessions, public.posts, public.comments, public.scores from anon, authenticated;

-- ---------- 공개 읽기용 뷰 (비밀번호 해시는 빠져 있음) ----------
create or replace view public.v_posts as
  select p.id, p.board, p.tag, p.title, p.body, p.nick,
         (p.member_id is not null) as is_member, p.ip_prefix, p.views, p.created_at,
         (select count(*) from public.comments c where c.post_ref = 'p' || p.id)::int as comment_count
  from public.posts p;

create or replace view public.v_comments as
  select c.id, c.post_ref, c.body, c.nick, (c.member_id is not null) as is_member, c.ip_prefix, c.created_at
  from public.comments c;

create or replace view public.v_ranks as
  select distinct on (s.game, s.nick) s.game, s.nick, (s.member_id is not null) as is_member, s.score, s.created_at
  from public.scores s
  order by s.game, s.nick, s.score desc, s.created_at asc;

create or replace view public.v_ai_counts as
  select post_ref, count(*)::int as comment_count from public.comments where post_ref like 'ai:%' group by post_ref;

grant select on public.v_posts, public.v_comments, public.v_ranks, public.v_ai_counts to anon, authenticated;

-- ---------- 내부 도우미 ----------
create or replace function private.ip_prefix() returns text
language plpgsql stable as $$
declare h json; ip text;
begin
  begin h := nullif(current_setting('request.headers', true), '')::json; exception when others then h := null; end;
  if h is null then return null; end if;
  ip := trim(split_part(coalesce(h->>'cf-connecting-ip', h->>'x-forwarded-for', h->>'x-real-ip', ''), ',', 1));
  if ip = '' then return null; end if;
  if position('.' in ip) > 0 then return split_part(ip,'.',1) || '.' || split_part(ip,'.',2); end if;
  return split_part(ip,':',1) || ':' || split_part(ip,':',2);
end $$;

create or replace function private.member_by_token(p_token text) returns public.members
language sql stable as $$
  select m.* from public.sessions s join public.members m on m.id = s.member_id
  where p_token is not null and s.token = p_token and s.expires_at > now()
$$;

create or replace function private.check_guest(p_nick text, p_pw text) returns text
language plpgsql stable as $$
declare n text := btrim(coalesce(p_nick,''));
begin
  if char_length(n) < 2 or char_length(n) > 12 then raise exception 'BAD_NICK'; end if;
  if n ~* '(운영|관리자|아열봇|admin)' then raise exception 'NICK_RESERVED'; end if;
  if exists (select 1 from public.members where nick = n) then raise exception 'NICK_RESERVED'; end if;
  if char_length(coalesce(p_pw,'')) < 4 or char_length(p_pw) > 72 then raise exception 'BAD_PW'; end if;
  return n;
end $$;

create or replace function private.new_session(p_member bigint) returns text
language plpgsql as $$
declare t text := encode(extensions.gen_random_bytes(24), 'hex');
begin
  delete from public.sessions where member_id = p_member and expires_at < now();
  insert into public.sessions(token, member_id) values (t, p_member);
  return t;
end $$;

revoke all on schema private from public, anon, authenticated;

-- ---------- 회원 ----------
create or replace function public.signup(p_login text, p_pw text, p_nick text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare l text := lower(btrim(coalesce(p_login,''))); n text := btrim(coalesce(p_nick,'')); mid bigint;
begin
  if l !~ '^[a-z0-9_]{4,16}$' then raise exception 'BAD_LOGIN_ID'; end if;
  if char_length(coalesce(p_pw,'')) < 4 or char_length(p_pw) > 72 then raise exception 'BAD_PW'; end if;
  if char_length(n) < 2 or char_length(n) > 12 then raise exception 'BAD_NICK'; end if;
  if n ~* '(운영|관리자|아열봇|admin)' then raise exception 'NICK_RESERVED'; end if;
  if n ~ '^[ㄱ-ㅎ]+$' or n in ('익명','유동','손님','guest') then raise exception 'NICK_FOR_GUEST'; end if;  -- 비회원이 자주 쓰는 닉네임은 고정닉으로 못 가져감
  if (select count(*) from members where created_at > now() - interval '10 minutes') >= 30 then raise exception 'BUSY'; end if;
  if exists (select 1 from members where login_id = l) then raise exception 'LOGIN_TAKEN'; end if;
  if exists (select 1 from members where nick = n) then raise exception 'NICK_TAKEN'; end if;
  insert into members(login_id, nick, pw_hash) values (l, n, crypt(p_pw, gen_salt('bf', 8))) returning id into mid;
  return json_build_object('token', private.new_session(mid), 'login_id', l, 'nick', n, 'is_admin', false);
end $$;

create or replace function public.login(p_login text, p_pw text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare m members;
begin
  select * into m from members where login_id = lower(btrim(coalesce(p_login,'')));
  if m.id is null or crypt(coalesce(p_pw,''), m.pw_hash) <> m.pw_hash then raise exception 'BAD_LOGIN'; end if;
  return json_build_object('token', private.new_session(m.id), 'login_id', m.login_id, 'nick', m.nick, 'is_admin', m.is_admin);
end $$;

create or replace function public.me(p_token text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare m members := private.member_by_token(p_token);
begin
  if m.id is null then return null; end if;
  return json_build_object('login_id', m.login_id, 'nick', m.nick, 'is_admin', m.is_admin);
end $$;

create or replace function public.logout(p_token text) returns void
language sql security definer set search_path = public as $$
  delete from sessions where token = p_token
$$;

create or replace function public.change_password(p_token text, p_old text, p_new text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare m members := private.member_by_token(p_token);
begin
  if m.id is null then raise exception 'NEED_LOGIN'; end if;
  if crypt(coalesce(p_old,''), m.pw_hash) <> m.pw_hash then raise exception 'BAD_LOGIN'; end if;
  if char_length(coalesce(p_new,'')) < 4 or char_length(p_new) > 72 then raise exception 'BAD_PW'; end if;
  update members set pw_hash = crypt(p_new, gen_salt('bf', 8)) where id = m.id;
  delete from sessions where member_id = m.id and token <> p_token;
end $$;

-- ---------- 게시글 ----------
create or replace function public.create_post(p_token text, p_board text, p_tag text, p_title text, p_body text, p_nick text, p_pw text) returns bigint
language plpgsql security definer set search_path = public, extensions as $$
declare m members := private.member_by_token(p_token); n text; ip text := private.ip_prefix(); t text := nullif(btrim(coalesce(p_tag,'')), ''); pid bigint;
begin
  if p_board not in ('free','notice') then raise exception 'BAD_BOARD'; end if;
  if p_board = 'notice' and (m.id is null or not m.is_admin) then raise exception 'NOT_ADMIN'; end if;
  if char_length(btrim(coalesce(p_title,''))) = 0 or char_length(btrim(coalesce(p_body,''))) = 0 then raise exception 'EMPTY'; end if;
  if char_length(p_title) > 60 or char_length(p_body) > 5000 then raise exception 'TOO_LONG'; end if;
  if t is not null and not (t = any (case when p_board = 'notice' then array['딴짓 꿀팁','공지','안내'] else array['잡담','질문','하소연','꿀팁'] end)) then raise exception 'BAD_TAG'; end if;
  if m.id is null then n := private.check_guest(p_nick, p_pw); else n := m.nick; end if;
  if not coalesce(m.is_admin, false) and exists (select 1 from posts where created_at > now() - interval '20 seconds'
             and (nick = n or (ip is not null and ip_prefix = ip and member_id is null and m.id is null))) then raise exception 'TOO_FAST'; end if;
  if not coalesce(m.is_admin, false) and (select count(*) from posts where created_at > now() - interval '1 minute') >= 20 then raise exception 'BUSY'; end if;
  insert into posts(board, tag, title, body, nick, member_id, pw_hash, ip_prefix)
  values (p_board, t, btrim(p_title), btrim(p_body), n, m.id,
          case when m.id is null then crypt(p_pw, gen_salt('bf', 8)) end,
          ip)
  returning id into pid;
  return pid;
end $$;

create or replace function public.delete_post(p_id bigint, p_token text, p_pw text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare m members := private.member_by_token(p_token); p posts;
begin
  select * into p from posts where id = p_id;
  if p.id is null then raise exception 'NOT_FOUND'; end if;
  if (m.id is not null and (m.is_admin or p.member_id = m.id))
     or (p.member_id is null and p.pw_hash is not null and p_pw is not null and crypt(p_pw, p.pw_hash) = p.pw_hash) then
    delete from comments where post_ref = 'p' || p_id;
    delete from posts where id = p_id;
    return;
  end if;
  raise exception 'NO_PERMISSION';
end $$;

create or replace function public.view_post(p_id bigint) returns void
language sql security definer set search_path = public as $$
  update posts set views = views + 1 where id = p_id
$$;

-- ---------- 댓글 ----------
create or replace function public.create_comment(p_ref text, p_token text, p_body text, p_nick text, p_pw text) returns bigint
language plpgsql security definer set search_path = public, extensions as $$
declare m members := private.member_by_token(p_token); n text; ip text := private.ip_prefix(); cid bigint;
begin
  if coalesce(p_ref,'') !~ '^(p[0-9]+|ai:[A-Za-z0-9_-]{1,40})$' then raise exception 'NOT_FOUND'; end if;
  if p_ref like 'p%' and not exists (select 1 from posts where id = substr(p_ref, 2)::bigint) then raise exception 'NOT_FOUND'; end if;
  if char_length(btrim(coalesce(p_body,''))) = 0 then raise exception 'EMPTY'; end if;
  if char_length(p_body) > 500 then raise exception 'TOO_LONG'; end if;
  if m.id is null then n := private.check_guest(p_nick, p_pw); else n := m.nick; end if;
  if exists (select 1 from comments where created_at > now() - interval '8 seconds'
             and (nick = n or (ip is not null and ip_prefix = ip and member_id is null and m.id is null))) then raise exception 'TOO_FAST'; end if;
  if (select count(*) from comments where created_at > now() - interval '1 minute') >= 60 then raise exception 'BUSY'; end if;
  insert into comments(post_ref, body, nick, member_id, pw_hash, ip_prefix)
  values (p_ref, btrim(p_body), n, m.id,
          case when m.id is null then crypt(p_pw, gen_salt('bf', 8)) end,
          ip)
  returning id into cid;
  return cid;
end $$;

create or replace function public.delete_comment(p_id bigint, p_token text, p_pw text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare m members := private.member_by_token(p_token); c comments;
begin
  select * into c from comments where id = p_id;
  if c.id is null then raise exception 'NOT_FOUND'; end if;
  if m.id is not null and (m.is_admin or c.member_id = m.id) then delete from comments where id = p_id; return; end if;
  if c.member_id is null and c.pw_hash is not null and p_pw is not null and crypt(p_pw, c.pw_hash) = c.pw_hash then delete from comments where id = p_id; return; end if;
  raise exception 'NO_PERMISSION';
end $$;

-- ---------- 게임 점수 ----------
create or replace function public.submit_score(p_game text, p_score integer, p_token text, p_nick text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
declare m members := private.member_by_token(p_token); n text; best integer;
begin
  if p_game not in ('runner','whack','slack') then raise exception 'BAD_GAME'; end if;
  if p_score is null or p_score <= 0 or p_score > (case p_game when 'runner' then 200000 when 'whack' then 3000 else 3600000 end) then raise exception 'BAD_SCORE'; end if;
  if m.id is null then
    n := btrim(coalesce(p_nick,''));
    if char_length(n) < 2 or char_length(n) > 12 then raise exception 'BAD_NICK'; end if;
    if n ~* '(운영|관리자|아열봇|admin)' or exists (select 1 from members where nick = n) then raise exception 'NICK_RESERVED'; end if;
  else n := m.nick; end if;
  if exists (select 1 from scores where nick = n and game = p_game and created_at > now() - interval '3 seconds') then return false; end if;
  select max(score) into best from scores where nick = n and game = p_game;
  if best is not null and best >= p_score then return false; end if;
  insert into scores(game, score, nick, member_id) values (p_game, p_score, n, m.id);
  return true;
end $$;

-- ---------- API 권한 ----------
revoke execute on all functions in schema public from public;
grant execute on function
  public.login(text,text), public.me(text), public.logout(text),
  public.change_password(text,text,text),
  public.create_post(text,text,text,text,text,text,text), public.delete_post(bigint,text,text), public.view_post(bigint),
  public.create_comment(text,text,text,text,text), public.delete_comment(bigint,text,text),
  public.submit_score(text,integer,text,text)
to anon, authenticated;

-- ---------- 글·댓글 수정 (임시 비밀번호 또는 운영진) ----------
create or replace function public.update_post(p_id bigint, p_token text, p_pw text, p_tag text, p_title text, p_body text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare m members := private.member_by_token(p_token); p posts; t text := nullif(btrim(coalesce(p_tag,'')), '');
begin
  select * into p from posts where id = p_id;
  if p.id is null then raise exception 'NOT_FOUND'; end if;
  if not ((m.id is not null and (m.is_admin or p.member_id = m.id))
          or (p.member_id is null and p.pw_hash is not null and p_pw is not null and crypt(p_pw, p.pw_hash) = p.pw_hash)) then
    raise exception 'NO_PERMISSION';
  end if;
  if char_length(btrim(coalesce(p_title,''))) = 0 or char_length(btrim(coalesce(p_body,''))) = 0 then raise exception 'EMPTY'; end if;
  if char_length(p_title) > 60 or char_length(p_body) > 5000 then raise exception 'TOO_LONG'; end if;
  if t is not null and not (t = any (case when p.board = 'notice' then array['딴짓 꿀팁','공지','안내'] else array['잡담','질문','하소연','꿀팁'] end)) then raise exception 'BAD_TAG'; end if;
  update posts set tag = t, title = btrim(p_title), body = btrim(p_body) where id = p_id;
end $$;

create or replace function public.update_comment(p_id bigint, p_token text, p_pw text, p_body text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare m members := private.member_by_token(p_token); c comments;
begin
  select * into c from comments where id = p_id;
  if c.id is null then raise exception 'NOT_FOUND'; end if;
  if not ((m.id is not null and (m.is_admin or c.member_id = m.id))
          or (c.member_id is null and c.pw_hash is not null and p_pw is not null and crypt(p_pw, c.pw_hash) = c.pw_hash)) then
    raise exception 'NO_PERMISSION';
  end if;
  if char_length(btrim(coalesce(p_body,''))) = 0 then raise exception 'EMPTY'; end if;
  if char_length(p_body) > 500 then raise exception 'TOO_LONG'; end if;
  update comments set body = btrim(p_body) where id = p_id;
end $$;

revoke execute on function public.update_post(bigint,text,text,text,text,text), public.update_comment(bigint,text,text,text) from public;
grant execute on function public.update_post(bigint,text,text,text,text,text), public.update_comment(bigint,text,text,text) to anon, authenticated;

-- 회원가입 닫기: 일반 이용자는 이름 + 임시 비밀번호로만 글을 씁니다. (운영자 로그인은 유지)
revoke execute on function public.signup(text,text,text) from anon, authenticated;

-- ---------- AI 글(공지·아열봇) 조회수 ----------
create table if not exists public.ai_views (
  post_ref text primary key check (post_ref ~ '^ai:[A-Za-z0-9_-]{1,40}$'),
  views    integer not null default 0
);
alter table public.ai_views enable row level security;
revoke all on public.ai_views from anon, authenticated;

create or replace view public.v_ai_stats as
  select coalesce(c.post_ref, v.post_ref) as post_ref, coalesce(c.comment_count, 0) as comment_count, coalesce(v.views, 0) as views
  from (select post_ref, count(*)::int as comment_count from public.comments where post_ref like 'ai:%' group by post_ref) c
  full join public.ai_views v on v.post_ref = c.post_ref;
grant select on public.v_ai_stats to anon, authenticated;

create or replace function public.view_ai(p_ref text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if coalesce(p_ref,'') !~ '^ai:[A-Za-z0-9_-]{1,40}$' then raise exception 'NOT_FOUND'; end if;
  insert into ai_views(post_ref, views) values (p_ref, 1)
  on conflict (post_ref) do update set views = ai_views.views + 1;
end $$;
revoke execute on function public.view_ai(text) from public;
grant execute on function public.view_ai(text) to anon, authenticated;

-- 운영자 지정 (사이트에서 회원가입한 뒤 아래 줄의 아이디를 바꿔 따로 실행):
-- update public.members set is_admin = true where login_id = '내아이디';
