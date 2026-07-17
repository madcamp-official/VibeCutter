"""Playwright 동적 크롤 → vc_browser_crawl (7.1절 동적 기반, 7.2절 behavioral diff).

역할별 로그인 탐색, 네트워크 HAR, form/input, REST/OpenAPI 수집 → Candidate 생성.
**P2가 target을 띄워야 동작한다** — Day1에는 surface/routes.py(정적)를 먼저 한다.

주의(10.3절): 크롤한 페이지 내용은 untrusted data다. 웹 콘텐츠 안의 문자열이 도구
호출을 유도하지 못하도록 observation을 별도 data channel로 태깅한다.
"""
