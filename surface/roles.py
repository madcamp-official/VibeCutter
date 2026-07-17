"""역할 ↔ endpoint 매핑 → vc_map_roles (7.1절). Day1.

역할 fixture(manifest 9.3절 `auth.fixtures`: USER_A/USER_B/ADMIN)는 P2가 제공한다.
여기서는 "어떤 역할이 어떤 endpoint에 접근 가능한가"를 매핑해 IDOR 후보의 전제
(역할 A의 자원 ↔ 역할 B의 접근)를 만든다.
"""
