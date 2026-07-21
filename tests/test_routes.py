"""surface.routes.extract_routes 단위 테스트 — Express handler 정의 파일 해석에 집중.

localizer가 소비하는 유일한 route 추출기. Node는 route 등록(server.ts)과 handler 정의
(routes/*.ts)가 분리되므로, route.source가 sink 있는 정의 파일을 짚어야 patch가 옳은 파일을 고친다.
"""

import tempfile
import unittest
from pathlib import Path

from surface.routes import extract_routes


def _tree(files: dict[str, str]) -> tempfile.TemporaryDirectory:
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return tmp


_SERVER = (
    "import { search } from './routes/search'\n"
    "const app = express()\n"
    "app.get('/rest/products/search', search())\n"
)
_SEARCH = (
    "export function search () {\n"
    "  return (req, res) => {\n"
    "    models.sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${req.query.q}%'`)\n"
    "  }\n"
    "}\n"
)


class ExpressRouteSourceTests(unittest.TestCase):
    def test_handler_source_points_to_definition_file_not_registration(self):
        # app.get(...)는 server.ts에 있지만 handler 정의는 routes/search.ts에 있다 → source는 정의 파일.
        with _tree({"server.ts": _SERVER, "routes/search.ts": _SEARCH}) as d:
            routes = extract_routes(d)
            r = next(r for r in routes if r.path == "/rest/products/search")
            self.assertEqual(r.handler, "search")
            self.assertTrue(r.source.startswith("routes/search.ts:"), r.source)
            self.assertNotIn("server.ts", r.source)

    def test_same_file_handler_keeps_registration_source(self):
        # 등록과 handler가 같은 파일이면 기존대로 등록 파일:라인 유지(무회귀).
        one = (
            "const app = express()\n"
            "function h () { return (req, res) => db.query(`SELECT ${req.query.q}`) }\n"
            "app.get('/x', h())\n"
        )
        with _tree({"app.js": one}) as d:
            routes = extract_routes(d)
            r = next(r for r in routes if r.path == "/x")
            self.assertTrue(r.source.startswith("app.js:"), r.source)


if __name__ == "__main__":
    unittest.main()
