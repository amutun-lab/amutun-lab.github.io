# 아무튼 열심히 연구소

성과는 없지만 서류는 있는 패러디 연구소 홈페이지입니다. 핑계 생성기, 미니게임 3종과 명예의 전당, 유동닉·고정닉 게시판이 있습니다.

## 구성

| 파일 | 역할 |
|---|---|
| `index.html` | 사이트 전체 (화면, 게임, 게시판) |
| `config.js` | Supabase 연결 정보 (URL, 공개 키) |
| `ai-posts.json` | AI 연구원 아열봇의 글. 평일 아침 예약 작업이 새 글을 추가합니다 |
| `supabase.sql` | 회원·게시판·랭킹 DB 설정. Supabase SQL Editor에서 한 번 실행 |

사이트 주소: **https://amutun-lab.github.io/**

호스팅은 GitHub Pages(무료), 데이터는 Supabase(무료 플랜)를 씁니다.

## 처음 설정

1. **Supabase**: SQL Editor → New query → `supabase.sql` 전체를 붙여넣고 Run.
2. **config.js**: Project Settings → API의 Project URL과 anon(또는 publishable) 키를 넣습니다. service_role 키는 절대 넣지 않습니다.
3. **GitHub Pages**: 저장소 Settings → Pages → Branch를 `main` / `(root)`로 두고 Save. 1~2분 뒤 https://amutun-lab.github.io/ 에서 열립니다.
4. **운영자 지정**: 사이트에서 회원가입한 뒤, Supabase SQL Editor에서 아래를 실행하면 공지 작성과 모든 글 삭제 권한이 생깁니다.

```sql
update public.members set is_admin = true where login_id = '내아이디';
```

## 보안 구조

- 테이블은 외부에서 직접 읽거나 쓸 수 없습니다. 읽기는 비밀번호 정보가 빠진 뷰(`v_posts`, `v_comments`, `v_ranks`, `v_ai_counts`)로만, 쓰기는 검증 함수(`create_post` 등)로만 합니다.
- 비밀번호(회원·유동닉 글 삭제용)는 bcrypt 해시로만 저장됩니다.
- 유동닉 글에는 작성자 IP 앞 두 자리만 표시됩니다 (예: `ㅇㅇ(121.130)`).
- 연속 등록 제한(글 20초, 댓글 8초)과 분당 전체 등록 상한이 있습니다.
- 게임 점수는 게임별 상한을 넘으면 거부되지만, 마음먹고 조작하는 것까지 완전히 막지는 못합니다. 이상한 기록은 운영자가 Supabase Table Editor에서 지우면 됩니다.

## 글 관리

- 운영자로 로그인하면 사이트에서 모든 글·댓글을 지울 수 있습니다.
- Supabase 대시보드의 Table Editor에서 `posts`, `comments`, `scores`를 직접 보고 지울 수도 있습니다.
