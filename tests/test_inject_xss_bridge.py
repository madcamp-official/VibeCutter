"""XSS·Injection suspect → Candidate 브리지(surface.candidates.injection_xss_candidates) 단위 테스트.

핸들러 inline SELECT SQLi → verify 가능한 injection Candidate, 서버 HTMLResponse → xss Candidate.
파괴적 write SQL·프론트 싱크는 blocked. 안전 파라미터화는 무시. 나온 candidate는 verifier probe로 파싱돼야 한다.
"""

import tempfile
import unittest
from pathlib import Path

from runtime.provisioning import ProvisioningStrategy, VerifierProvisioning
from surface.candidates import candidates_for_target, injection_xss_candidates
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
# 줄 넘는 SQL sink(대입 후 실행) — candidate 빌더도 프리필터와 같은 규칙을 써야 한다(sync).
_CROSS_LINE_PY = '@app.get("/cl")\ndef c(q: str):\n    sql = f"SELECT * FROM t WHERE x = \'{q}\'"\n    return db.execute(sql)\n'
# 주석 처리된 SQL — candidate 안 만들어야(precision)
_COMMENT_PY = '@app.get("/cm")\ndef c(q: str):\n    # return db.execute(f"SELECT * FROM t WHERE x = \'{q}\'")\n    return safe(q)\n'
# 인라인 arrow 핸들러(심볼 없이 라우트에 직접) 안의 SQLi — _node_handlers 인라인 추출 필요.
_INLINE_ARROW = "router.get('/inline', (req, res) => {\n  const sql = `SELECT * FROM t WHERE n = '${req.query.q}'`\n  return db.query(sql)\n})\n"


class EntryPointWiringTests(unittest.TestCase):
    """candidates_for_target(MCP scan tool 단일 진입점)이 IDOR뿐 아니라 injection/XSS도 내는지.

    이전엔 IDOR만 냈고 injection_xss_candidates는 어디서도 안 불려 실제 audit에 안 닿았다(배선 gap).
    """

    def _prov_ir(self):
        return VerifierProvisioning(target_id="t", base_url="http://127.0.0.1:9",
                                    strategy=ProvisioningStrategy.CONTRACT_REQUIRED,
                                    auth_mode="none", notes="test")

    def test_entry_point_yields_injection_and_xss_candidates(self):
        files = {
            "s.ts": "router.get('/s', (req,res)=>{\n  const sql = `SELECT * FROM p WHERE n = '${req.query.q}'`\n  return db.query(sql)\n})\n",
            "v.py": '@app.get("/v")\ndef v(name: str):\n    return mark_safe(f"<h1>{name}</h1>")\n',
        }
        with _tree(files) as d:
            classes = {c.vuln_class for c in candidates_for_target("r", self._prov_ir(), d).candidates}
        self.assertIn("injection", classes)
        self.assertIn("xss", classes)


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

    def test_cross_line_python_sqli_becomes_candidate(self):
        # candidate 빌더가 프리필터와 sync — 줄 넘는 SQL(대입 후 실행)도 후보로 만든다.
        with _tree({"app.py": _CROSS_LINE_PY}) as d:
            inj = [c for c in injection_xss_candidates("r", _prov(), d).candidates if c.vuln_class == "injection"]
            self.assertEqual(len(inj), 1)
            self.assertEqual(inj[0].attack_params["inject_param"], "q")

    def test_commented_sql_yields_no_candidate(self):
        # 주석 처리된 SQL은 후보로 만들지 않는다(precision — 프리필터와 sync).
        with _tree({"app.py": _COMMENT_PY}) as d:
            res = injection_xss_candidates("r", _prov(), d)
            self.assertEqual([c for c in res.candidates if c.vuln_class == "injection"], [])

    def test_inline_arrow_node_sqli_becomes_candidate(self):
        # 심볼 없이 라우트에 직접 박힌 인라인 arrow 핸들러 본문의 SQLi도 후보로(_node_handlers 인라인 추출).
        with _tree({"routes.ts": _INLINE_ARROW}) as d:
            inj = [c for c in injection_xss_candidates("r", _prov(), d).candidates if c.vuln_class == "injection"]
            self.assertEqual(len(inj), 1)
            self.assertEqual(inj[0].attack_params["inject_path"], "/inline")
            self.assertEqual(inj[0].attack_params["inject_param"], "q")

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

    def test_server_template_xss_becomes_candidate(self):
        # 후보 경로도 프리필터와 sync — mark_safe/render_template_string 서버 sink도 XSS 후보로.
        for src in ('@app.get("/ms")\ndef v(name: str):\n    return mark_safe(f"<h1>{name}</h1>")\n',
                    '@app.get("/rt")\ndef v(name: str):\n    return render_template_string(f"<p>{name}</p>")\n'):
            with _tree({"app.py": src}) as d:
                x = [c for c in injection_xss_candidates("r", _prov(), d).candidates if c.vuln_class == "xss"]
                self.assertEqual(len(x), 1)
                self.assertEqual(x[0].attack_params["inject_param"], "name")

    def test_literal_server_xss_yields_no_candidate(self):
        # 정적 리터럴을 mark_safe 하는 건 무해 → 후보 안 만듦(precision)
        with _tree({"app.py": '@app.get("/s")\ndef v():\n    return mark_safe("<b>static</b>")\n'}) as d:
            res = injection_xss_candidates("r", _prov(), d)
            self.assertEqual([c for c in res.candidates if c.vuln_class == "xss"], [])

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
