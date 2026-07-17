"""XSS verifier (7.3절). Day2 착수 ~ Day3 완성.

검증 oracle: "격리 브라우저에서 지정된 benign marker가 실행/DOM 삽입됐는지".
benign marker만 쓴다 — 컨테이너 밖으로 나가는 payload, reverse connection, 지속성
행위는 지원하지 않는다(7.3절, 10.4절).
"""
