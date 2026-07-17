"""Broken Access Control / IDOR verifier (7.3절, CWE-639). P0 — MVP의 승부처.

검증 oracle (7.3절 표): "역할 A가 만든 자원을 역할 B가 읽거나 변경했는지 DB/API 상태 비교".
즉 응답 코드 200 하나로 verified를 만들지 않는다 — 실제 상태 변화(또는 권한 없는 데이터
노출)를 관찰해야 한다.

11.5절 P0: "IDOR verifier + patch loop — 한 취약점을 발견·수정·재검증".
16장: "IDOR 한 종류라도 발견→재현→코드 위치→패치→재공격→정상 기능 통과를 먼저 완성해야 한다."

Day2 완료 기준: IDOR verified 1건 이상.
"""
