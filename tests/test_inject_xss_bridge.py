"""XSS·Injection suspect → Candidate 브리지(surface.candidates.injection_xss_candidates) 단위 테스트.

핸들러 inline SELECT SQLi → verify 가능한 injection Candidate, 서버 HTMLResponse → xss Candidate.
파괴적 write SQL·프론트 싱크는 blocked. 안전 파라미터화는 무시. 나온 candidate는 verifier probe로 파싱돼야 한다.
"""

import tempfile
import unittest
from pathlib import Path

from runtime.provisioning import ProvisioningStrategy, VerifierProvisioning
from surface.candidates import injection_xss_candidates
from verifiers import injection, xss


def _tree(files: dict[str, str]) -> tempfile.TemporaryDirectory:
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return tmp


def _prov(tid: str = "t") -> VerifierProvisioning:
    return VerifierProvisioning(
        target_id=tid, base_url="http://127.0.0.1:9",
        strategy=ProvisioningStrategy.SELF_SIGNUP, auth_mode="none", notes="test",
    )


_GET_SQLI = '@app.get("/search")\ndef s(q: str):\n    return db.execute(f"SELECT * FROM t WHERE x = \'{q}\'")\n'
_HTML_XSS = '@app.get("/render")\ndef r(name: str):\n    return HTMLResponse(f"<h1>{name}</h1>")\n'
_WRITE_SQL = '@app.post("/items/{i}")\ndef rm(i: int):\n    return db.execute(f"DELETE FROM t WHERE id = {i}")\n'
_SAFE_PARAM = '@app.get("/safe")\ndef s(q: str):\n    return db.execute("SELECT * FROM t WHERE x = $1", (q,))\n'


class InjectionXssBridgeTests(unittest.TestCase):
    def test_get_select_sqli_becomes_verifiable_injection_candidate(self):
        with _tree({"app.py": _GET_SQLI}) as d:
            res = injection_xss_candidates("r", _prov(), d)
            inj = [c for c in res.candidates if c.vuln_class == "injection"]
            self.assertEqual(len(inj), 1)
            self.assertEqual(inj[0].attack_params["inject_path"], "/search")
            self.assertEqual(inj[0].attack_params["base_url"], "http://127.0.0.1:9")
            # verify-ready: 실제 verifier probe로 파싱돼야 한다
            p = injection.injection_probe_from_candidate(inj[0])
            self.assertEqual(p.inject_param, "q")
            self.assertEqual(p.inject_method, "GET")

    def test_htmlresponse_becomes_verifiable_xss_candidate(self):
        with _tree({"app.py": _HTML_XSS}) as d:
            res = injection_xss_candidates("r", _prov(), d)
            x = [c for c in res.candidates if c.vuln_class == "xss"]
            self.assertEqual(len(x), 1)
            p = xss.xss_probe_from_candidate(x[0])
            self.assertEqual(p.inject_path, "/render")
            self.assertEqual(p.context, "reflected")
            self.assertEqual(p.inject_param, "name")

    def test_write_sql_is_blocked_not_candidate(self):
        # 파괴적 write SQL은 불리언 payload가 위험 → candidate로 만들지 않고 blocked
        with _tree({"app.py": _WRITE_SQL}) as d:
            res = injection_xss_candidates("r", _prov(), d)
            self.assertEqual([c for c in res.candidates if c.vuln_class == "injection"], [])
            self.assertTrue(any("write SQL" in b.reason for b in res.blocked))

    def test_frontend_sink_is_blocked(self):
        with _tree({"C.tsx": "export const C = ({h}) => <div dangerouslySetInnerHTML={{__html: h}} />;\n"}) as d:
            res = injection_xss_candidates("r", _prov(), d)
            self.assertEqual(res.candidates, [])
            self.assertTrue(any("프론트 XSS" in b.reason for b in res.blocked))

    def test_parameterized_query_yields_no_candidate(self):
        with _tree({"app.py": _SAFE_PARAM}) as d:
            res = injection_xss_candidates("r", _prov(), d)
            self.assertEqual(res.candidates, [])
            self.assertEqual(res.blocked, [])

    def test_clean_no_handlers_is_empty(self):
        with _tree({"util.py": "def add(a, b):\n    return a + b\n"}) as d:
            res = injection_xss_candidates("r", _prov(), d)
            self.assertEqual(res.candidates, [])
            self.assertEqual(res.blocked, [])


if __name__ == "__main__":
    unittest.main()
