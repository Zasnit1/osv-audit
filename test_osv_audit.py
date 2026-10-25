import json

import osv_audit as oa

REQS = """
# project deps
Django==2.2.0
requests==2.19.1
clean-lib==1.0.0
-e .
"""

LOCK = json.dumps({
    "name": "app", "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "version": "1.0.0"},
        "node_modules/lodash": {"name": "lodash", "version": "4.17.11"},
        "node_modules/leftpad": {"name": "leftpad", "version": "0.0.1"},
    },
})


def test_parse_requirements():
    pkgs = oa.parse_requirements(REQS)
    names = {(p.name, p.version, p.ecosystem) for p in pkgs}
    assert ("Django", "2.2.0", "PyPI") in names
    assert ("requests", "2.19.1", "PyPI") in names
    assert all(p.ecosystem == "PyPI" for p in pkgs)
    assert len(pkgs) == 3  # the "-e ." line is skipped


def test_parse_package_lock():
    pkgs = oa.parse_package_lock(LOCK)
    names = {(p.name, p.version) for p in pkgs}
    assert ("lodash", "4.17.11") in names
    assert ("leftpad", "0.0.1") in names
    assert all(p.ecosystem == "npm" for p in pkgs)


def test_load_packages_dispatch():
    assert oa.load_packages("requirements.txt", REQS)[0].ecosystem == "PyPI"
    assert oa.load_packages("package-lock.json", LOCK)[0].ecosystem == "npm"


def test_fixed_version_extraction():
    detail = {"affected": [{"package": {"name": "Django"},
                            "ranges": [{"type": "ECOSYSTEM",
                                        "events": [{"introduced": "0"}, {"fixed": "2.2.1"}]}]}]}
    pkg = oa.Package("Django", "2.2.0", "PyPI")
    assert oa.fixed_version(detail, pkg) == "2.2.1"
    assert oa.fixed_version({"affected": []}, pkg) == ""


def test_query_osv_with_injected_fetch():
    pkgs = [oa.Package("Django", "2.2.0", "PyPI"), oa.Package("clean-lib", "1.0.0", "PyPI")]

    def fake_batch(url, payload, timeout):
        return {"results": [{"vulns": [{"id": "GHSA-xxxx"}]}, {}]}

    def fake_detail(url, timeout):
        return {"summary": "SQL injection in Django",
                "affected": [{"package": {"name": "Django"},
                              "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.2.1"}]}]}]}

    vulns = oa.query_osv(pkgs, 5.0, fetch=fake_batch, fetch_one=fake_detail)
    assert len(vulns) == 1
    v = vulns[0]
    assert v.package == "Django" and v.id == "GHSA-xxxx" and v.fixed == "2.2.1"
    assert "SQL injection" in v.summary


def test_render_and_exit_semantics(tmp_path, monkeypatch):
    req = tmp_path / "requirements.txt"
    req.write_text("Django==2.2.0\n")

    def fake_query(pkgs, timeout):
        return [oa.Vuln("Django", "2.2.0", "PyPI", "GHSA-xxxx", "SQL injection", "2.2.1")]

    monkeypatch.setattr(oa, "query_osv", fake_query)
    assert oa.main([str(req), "--format", "json", "--fail-on-vuln"]) == 2

    def no_vulns(pkgs, timeout):
        return []

    monkeypatch.setattr(oa, "query_osv", no_vulns)
    assert oa.main([str(req), "--fail-on-vuln"]) == 0


def test_render_text_clean():
    assert "No known vulnerabilities" in oa.render_text([], 5)
