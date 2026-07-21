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

# Node/Express (Juice Shop 구조): 라우트 등록과 핸들러 정의가 다른 파일. SQL 결합 변수(criteria)가
# HTTP 파라미터(q)와 다르다 — verify는 SQL 변수가 아니라 req.query.q를 때려야 한다.
_JS_SERVER = "import { search } from './routes/search'\napp.get('/rest/products/search', search())\n"
_JS_SEARCH = (
    "export function search () {\n"
    "  return (req, res, next) => {\n"
    "    let criteria = req.query.q ?? ''\n"
    "    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)\n"
    "    models.sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${criteria}%' AND deletedAt IS NULL`)\n"
    "      .then((p) => res.json(p)).catch(next)\n"
    "  }\n"
    "}\n"
)
# 로그인 SQLi: SQL 라인에 req.body.email 직접 결합 → 파라미터 email.
_JS_LOGIN = (
    "app.post('/rest/user/login', login())\n"
    "export function login () {\n"
    "  return (req, res) => {\n"
    "    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}' AND deletedAt IS NULL`)\n"
    "  }\n"
    "}\n"
)


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

    def test_node_sqli_traces_http_param_not_sql_variable(self):
        # 데모 2(J-3) 잠금: Juice Shop처럼 route와 handler가 다른 파일이고 SQL 변수(criteria)≠HTTP
        # 파라미터(q)일 때, candidate가 verify용으로 SQL 변수가 아니라 req.query.q를 잡아야 한다.
        with _tree({"server.ts": _JS_SERVER, "routes/search.ts": _JS_SEARCH}) as d:
            res = injection_xss_candidates("r", _prov(), d)
            inj = [c for c in res.candidates if c.vuln_class == "injection"]
            self.assertEqual(len(inj), 1)
            self.assertEqual(inj[0].attack_params["inject_path"], "/rest/products/search")
            self.assertEqual(inj[0].attack_params["inject_param"], "q")  # criteria가 아니라 q
            p = injection.injection_probe_from_candidate(inj[0])
            self.assertEqual(p.inject_param, "q")
            self.assertEqual(p.inject_method, "GET")

    def test_node_candidate_source_symbol_points_to_sink_file_not_route_file(self):
        # 패치 대상은 route 등록 파일(server.ts)이 아니라 SQL sink이 있는 handler 파일(routes/search.ts).
        # source_symbols는 localizer/patch가 소비하는 "파일:라인" 형식이어야 한다.
        with _tree({"server.ts": _JS_SERVER, "routes/search.ts": _JS_SEARCH}) as d:
            res = injection_xss_candidates("r", _prov(), d)
            inj = [c for c in res.candidates if c.vuln_class == "injection"]
            self.assertEqual(len(inj), 1)
            sym = inj[0].source_symbols[0]
            self.assertTrue(sym.startswith("routes/search.ts:"), f"sink 파일 아님: {sym}")
            self.assertNotIn("server.ts", sym)

    def test_node_inline_request_access_resolves_param(self):
        # SQL 라인에 req.body.email 직접 결합 → 파라미터 email로 잡는다.
        with _tree({"routes/login.ts": _JS_LOGIN}) as d:
            res = injection_xss_candidates("r", _prov(), d)
            inj = [c for c in res.candidates if c.vuln_class == "injection"]
            self.assertEqual(len(inj), 1)
            self.assertEqual(inj[0].attack_params["inject_param"], "email")

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
