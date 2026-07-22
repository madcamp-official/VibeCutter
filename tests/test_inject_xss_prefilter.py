"""XSS·Injection 프리필터(surface/inject_xss.py) 단위 테스트 — 임시 소스로 CI에서 돈다.

핵심은 precision: **취약한 동적 결합/sink는 잡고, 안전한 파라미터화·ORM·리터럴·살균·로그는 제외**한다.
"""

import tempfile
import unittest
from pathlib import Path

from surface.inject_xss import find_injection_suspects, find_xss_suspects


def _tree(files: dict[str, str]) -> tempfile.TemporaryDirectory:
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return tmp


class InjectionPrefilterTests(unittest.TestCase):
    def test_detects_python_fstring_sql(self):
        with _tree({"dao.py": 'def q(db, u):\n    return db.execute(f"SELECT * FROM users WHERE name = \'{u}\'")\n'}) as d:
            sus = find_injection_suspects(d)
            self.assertEqual(len(sus), 1)
            self.assertEqual(sus[0].inject_param, "u")

    def test_detects_node_template_literal_sql(self):
        with _tree({"repo.js": "export function s(q){ return db.query(`SELECT id FROM items WHERE t = '${q}'`); }\n"}) as d:
            self.assertEqual(len(find_injection_suspects(d)), 1)

    def test_detects_string_concat_sql(self):
        with _tree({"dao.py": 'def q(db, u):\n    return db.execute("SELECT * FROM t WHERE n = \'" + u + "\'")\n'}) as d:
            self.assertEqual(len(find_injection_suspects(d)), 1)

    def test_rejects_parameterized_binding(self):
        with _tree({"dao.py": 'def q(db, u):\n    return db.execute("SELECT * FROM users WHERE name = %s", (u,))\n'}) as d:
            self.assertEqual(find_injection_suspects(d), [])

    def test_rejects_orm_filter(self):
        with _tree({"dao.py": "def q(db, u):\n    return db.query(User).filter(User.name == u).first()\n"}) as d:
            self.assertEqual(find_injection_suspects(d), [])

    def test_rejects_logging_line_with_from(self):
        # 영어 'from'이 든 로그 문장은 쿼리가 아니다 → 오탐 안 함 (c3-08 scheduler.ts 실측 오탐 회귀 방지)
        with _tree({"s.ts": "console.log(`processed ${n} message(s) from ${src}`);\n"}) as d:
            self.assertEqual(find_injection_suspects(d), [])

    def test_rejects_sql_string_without_execution(self):
        # SQL 문자열+동적 결합이라도 실행 지점(execute/query/…) 없으면 보수적으로 제외
        with _tree({"x.py": 'msg = f"select items from {menu}"\n'}) as d:
            self.assertEqual(find_injection_suspects(d), [])

    def test_detects_cross_line_assign_then_execute(self):
        # 줄 넘는 sink: 동적 SQL을 변수에 만들고 다음 줄에서 실행 (문서화된 최대 recall 공백 해소)
        src = 'def q(db, name):\n    sql = f"SELECT * FROM users WHERE name = \'{name}\'"\n    return db.execute(sql)\n'
        with _tree({"dao.py": src}) as d:
            sus = find_injection_suspects(d)
            self.assertEqual(len(sus), 1)
            self.assertEqual(sus[0].line, 2)          # 대입 라인(문자열 구성=고칠 지점)을 sink으로
            self.assertEqual(sus[0].inject_param, "name")

    def test_detects_cross_line_concat_node(self):
        src = "function h(uid){\n  const sql = 'SELECT * FROM a WHERE id = ' + uid\n  return db.query(sql)\n}\n"
        with _tree({"repo.ts": src}) as d:
            self.assertEqual(len(find_injection_suspects(d)), 1)

    def test_cross_line_reassigned_safe_is_not_flagged(self):
        # 동적 SQL을 만들었다가 실행 전에 안전한(파라미터화) 값으로 재대입하면 오염 해제 → 제외(precision)
        src = ('def q(db, u):\n'
               '    sql = f"SELECT * FROM t WHERE x = \'{u}\'"\n'
               '    sql = "SELECT * FROM t WHERE x = ?"\n'
               '    return db.execute(sql, (u,))\n')
        with _tree({"dao.py": src}) as d:
            self.assertEqual(find_injection_suspects(d), [])

    def test_cross_line_execution_too_far_is_not_flagged(self):
        # 대입과 실행이 창(_EXEC_WINDOW) 밖으로 멀면 같은 sink으로 보지 않는다(오염 전파 추정 제한)
        far = "def q(db, u):\n    sql = f\"SELECT * FROM t WHERE x = '{u}'\"\n" + "    pass\n" * 8 + "    return db.execute(sql)\n"
        with _tree({"dao.py": far}) as d:
            self.assertEqual(find_injection_suspects(d), [])


class XssPrefilterTests(unittest.TestCase):
    def test_detects_dynamic_dangerously_set_inner_html(self):
        with _tree({"C.tsx": "export const C = ({html}) => <div dangerouslySetInnerHTML={{__html: html}} />;\n"}) as d:
            sus = find_xss_suspects(d)
            self.assertEqual(len(sus), 1)
            self.assertEqual(sus[0].sink, "dangerouslySetInnerHTML")

    def test_rejects_literal_html(self):
        with _tree({"C.tsx": 'export const C = () => <div dangerouslySetInnerHTML={{__html: "<b>x</b>"}} />;\n'}) as d:
            self.assertEqual(find_xss_suspects(d), [])

    def test_rejects_sanitized_value(self):
        with _tree({"C.tsx": "export const C = ({raw}) => <div dangerouslySetInnerHTML={{__html: sanitize(raw)}} />;\n"}) as d:
            self.assertEqual(find_xss_suspects(d), [])

    def test_rejects_vendored_design_tool_dir(self):
        # 앱 로직이 아닌 벤더/디자인툴(_ds) 파일은 스캔 제외 (c1-05 design/_ds 실측 오탐 회귀 방지)
        with _tree({"design/_ds/support.js": "tpl.innerHTML = build(x);\n"}) as d:
            self.assertEqual(find_xss_suspects(d), [])

    def test_detects_vue_v_html(self):
        with _tree({"C.vue": '<template><div v-html="userBio"></div></template>\n'}) as d:
            sus = find_xss_suspects(d)
            self.assertEqual(len(sus), 1)
            self.assertEqual(sus[0].sink, "v-html")


if __name__ == "__main__":
    unittest.main()
