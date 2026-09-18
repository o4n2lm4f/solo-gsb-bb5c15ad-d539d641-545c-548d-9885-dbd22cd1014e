"""POST /sbom 的端到端测试。

覆盖：有效锁上的确定性清单导出（规范化名 / 版本 / PURL / 依赖名 / 元数据）、
包名排序、元数据缺失只产生 warnings 不阻断导出、空白元数据视为缺失、
marker 未激活依赖不进入清单、锁无效时 409 短路（issues 与 /audit-lock
一致）、PEP 503/440 等价性、依赖环安全、确定性（与输入键顺序无关），
以及 422（非法快照 / 锁 / 请求）映射与既有接口兼容性。
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

ENV = {
    "python_version": "3.11",
    "sys_platform": "linux",
    "platform_machine": "x86_64",
}
WIN_ENV = {
    "python_version": "3.11",
    "sys_platform": "win32",
    "platform_machine": "AMD64",
}

SHA_APP = "a" * 64
SHA_LIBX = "b" * 64
SHA_LIBY = "c" * 64


def c(version, deps=None, **meta):
    return {"version": version, "dependencies": deps or [], **meta}


def d(name, spec="", marker=""):
    return {"name": name, "specifier": spec, "marker": marker}


def sbom(repo, lock, *, root="app", env=None, **overrides):
    body = {
        "repository": repo,
        "root": root,
        "target_environment": env or ENV,
        "current_lock": lock,
    }
    body.update(overrides)
    return client.post("/sbom", json=body)


def export(repo, lock, **kw):
    r = sbom(repo, lock, **kw)
    assert r.status_code == 200, r.text
    return r.json()


def full_repo():
    """全部候选携带完整元数据的菱形依赖快照。"""
    return {
        "app": [c("1.0.0", [d("libx", ">=1.0")],
                  source_url="https://example.invalid/app-1.0.0.tar.gz",
                  sha256=SHA_APP, license="MIT")],
        "libx": [
            c("1.0", source_url="https://example.invalid/libx-1.0.tar.gz",
              sha256=SHA_LIBX, license="Apache-2.0"),
            c("2.0", [d("liby")],
              source_url="https://example.invalid/libx-2.0.tar.gz",
              sha256=SHA_LIBX, license="Apache-2.0"),
        ],
        "liby": [c("1.1", source_url="https://example.invalid/liby-1.1.tar.gz",
                   sha256=SHA_LIBY, license="BSD-3-Clause")],
    }


# --------------------------------------------------------------------- #
# 1. 基本导出：字段、排序、PURL、warnings
# --------------------------------------------------------------------- #
def test_sbom_ok_full_metadata_no_warnings():
    body = export(full_repo(), {"app": "1.0.0", "libx": "2.0", "liby": "1.1"})
    assert body["status"] == "ok"
    assert body["root"] == "app"
    assert body["root_version"] == "1.0.0"
    assert body["warnings"] == []
    assert [p["name"] for p in body["packages"]] == ["app", "libx", "liby"]
    assert body["packages"][0] == {
        "name": "app",
        "version": "1.0.0",
        "purl": "pkg:pypi/app@1.0.0",
        "dependencies": ["libx"],
        "source_url": "https://example.invalid/app-1.0.0.tar.gz",
        "sha256": SHA_APP,
        "license": "MIT",
    }
    assert body["packages"][1]["dependencies"] == ["liby"]
    assert body["packages"][1]["purl"] == "pkg:pypi/libx@2.0"
    assert body["packages"][2]["dependencies"] == []


def test_sbom_missing_metadata_warns_but_exports():
    repo = {
        "app": [c("1.0", [d("libx")], license="MIT")],  # 缺 source_url/sha256
        "libx": [c("2.0", sha256=SHA_LIBX)],            # 缺 source_url/license
    }
    body = export(repo, {"app": "1.0", "libx": "2.0"})
    assert body["status"] == "ok"
    app_entry, libx_entry = body["packages"]
    assert app_entry["source_url"] is None
    assert app_entry["sha256"] is None
    assert app_entry["license"] == "MIT"
    assert libx_entry["source_url"] is None
    assert libx_entry["sha256"] == SHA_LIBX
    assert libx_entry["license"] is None
    # 每个缺失字段一条 warning，按 (包名, 字段声明顺序) 排列。
    assert body["warnings"] == [
        {"package": "app", "field": "source_url",
         "message": "包 app==1.0 缺少元数据字段 source_url"},
        {"package": "app", "field": "sha256",
         "message": "包 app==1.0 缺少元数据字段 sha256"},
        {"package": "libx", "field": "source_url",
         "message": "包 libx==2.0 缺少元数据字段 source_url"},
        {"package": "libx", "field": "license",
         "message": "包 libx==2.0 缺少元数据字段 license"},
    ]


def test_sbom_blank_metadata_treated_as_missing():
    repo = {"app": [c("1.0", source_url="   ", sha256="", license="MIT")]}
    body = export(repo, {"app": "1.0"})
    entry = body["packages"][0]
    assert entry["source_url"] is None
    assert entry["sha256"] is None
    assert entry["license"] == "MIT"
    assert [w["field"] for w in body["warnings"]] == ["source_url", "sha256"]


def test_sbom_packages_sorted_by_name_not_lock_order():
    repo = {
        "zeta": [c("1.0", license="MIT")],
        "app": [c("1.0", [d("zeta"), d("alpha")], license="MIT")],
        "alpha": [c("1.0", license="MIT")],
    }
    lock = {"zeta": "1.0", "app": "1.0", "alpha": "1.0"}
    body = export(repo, lock)
    assert [p["name"] for p in body["packages"]] == ["alpha", "app", "zeta"]
    app_entry = body["packages"][1]
    assert app_entry["dependencies"] == ["alpha", "zeta"]


def test_sbom_deterministic_regardless_of_input_key_order():
    repo1 = full_repo()
    repo2 = dict(reversed(list(full_repo().items())))
    lock = {"liby": "1.1", "libx": "2.0", "app": "1.0.0"}
    body1 = export(repo1, lock)
    body2 = export(repo2, dict(reversed(list(lock.items()))))
    assert body1 == body2


# --------------------------------------------------------------------- #
# 2. 图语义：marker 激活、PEP 503/440 等价、环安全
# --------------------------------------------------------------------- #
def test_sbom_only_active_marker_dependencies_listed():
    repo = {
        "app": [c("1.0", [
            d("linux-only", marker="sys_platform == 'linux'"),
            d("win-only", marker="sys_platform == 'win32'"),
        ], license="MIT")],
        "linux-only": [c("1.0", license="MIT")],
        "win-only": [c("1.0", license="MIT")],
    }
    lock = {"app": "1.0", "linux-only": "1.0"}
    body = export(repo, lock)
    assert [p["name"] for p in body["packages"]] == ["app", "linux-only"]
    assert body["packages"][0]["dependencies"] == ["linux-only"]

    # 同一快照切到 Windows：依赖图与清单随之变化。
    body_win = export(repo, {"app": "1.0", "win-only": "1.0"}, env=WIN_ENV)
    assert [p["name"] for p in body_win["packages"]] == ["app", "win-only"]


def test_sbom_pep503_pep440_equivalence():
    """锁中 Some_Pkg / 1.0 与快照 some-pkg / 1.0.0 视为同一包同一版本。"""
    repo = {
        "App": [c("1.0.0", [d("Some_Pkg")], license="MIT")],
        "some-pkg": [c("1.0.0", sha256=SHA_LIBX)],
    }
    lock = {"app": "1.0", "some.pkg": "1.0"}
    body = export(repo, lock, root="App")
    assert [p["name"] for p in body["packages"]] == ["app", "some-pkg"]
    # 版本/PURL 使用锁中文本；元数据取自快照等价版本。
    assert body["packages"][0]["version"] == "1.0"
    assert body["packages"][0]["purl"] == "pkg:pypi/app@1.0"
    assert body["packages"][1]["sha256"] == SHA_LIBX
    assert body["packages"][1]["license"] is None


def test_sbom_cycle_safe():
    repo = {
        "app": [c("1.0", [d("liba")], license="MIT")],
        "liba": [c("1.0", [d("libb")], license="MIT")],
        "libb": [c("1.0", [d("liba")], license="MIT")],  # 回边成环
    }
    lock = {"app": "1.0", "liba": "1.0", "libb": "1.0"}
    body = export(repo, lock)
    by_name = {p["name"]: p for p in body["packages"]}
    assert by_name["libb"]["dependencies"] == ["liba"]
    assert by_name["liba"]["dependencies"] == ["libb"]


# --------------------------------------------------------------------- #
# 3. 锁审计短路：409 与 /audit-lock 一致
# --------------------------------------------------------------------- #
def test_sbom_invalid_lock_409_matches_audit_issues():
    repo = {
        "app": [c("1.0", [d("libx", ">=2.0"), d("ghost")])],
        "libx": [c("2.0"), c("1.0")],
    }
    lock = {"app": "1.0", "libx": "1.0", "stale": "0.1"}  # 多种问题
    r = sbom(repo, lock)
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["status"] == "invalid_lock"
    assert "packages" not in body
    assert "warnings" not in body

    audit = client.post("/audit-lock", json={
        "repository": repo,
        "root": "app",
        "target_environment": ENV,
        "current_lock": lock,
    })
    assert audit.status_code == 200
    assert body["issues"] == audit.json()["issues"]
    types = {issue["type"] for issue in body["issues"]}
    assert types == {"missing", "constraint_mismatch", "extraneous"}


def test_sbom_unavailable_locked_version_409():
    repo = {"app": [c("1.0")]}
    r = sbom(repo, {"app": "9.9"})
    assert r.status_code == 409
    assert r.json()["issues"][0]["type"] == "unavailable"


# --------------------------------------------------------------------- #
# 4. 422：非法快照 / 锁 / 请求
# --------------------------------------------------------------------- #
def test_sbom_unknown_root_422():
    r = sbom({"app": [c("1.0")]}, {"app": "1.0"}, root="missing")
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_snapshot"


def test_sbom_bad_lock_version_422():
    r = sbom({"app": [c("1.0")]}, {"app": "oops"})
    assert r.status_code == 422
    assert "PEP 440" in r.json()["message"]


def test_sbom_conflicting_lock_versions_422():
    r = sbom({"app": [c("1.0")]}, {"App": "1.0", "app": "2.0"})
    assert r.status_code == 422


def test_sbom_bad_marker_still_422():
    repo = {"app": [c("1.0", [d("x", marker="python_version >>> '3.9'")])]}
    r = sbom(repo, {"app": "1.0"})
    assert r.status_code == 422
    assert "PEP 508" in r.json()["message"]


def test_sbom_extra_request_field_422():
    r = sbom({"app": [c("1.0")]}, {"app": "1.0"}, unknown_field=1)
    assert r.status_code == 422


def test_sbom_candidate_unknown_metadata_field_422():
    repo = {"app": [{"version": "1.0", "homepage": "https://x.invalid"}]}
    r = sbom(repo, {"app": "1.0"})
    assert r.status_code == 422


def test_sbom_duplicate_candidate_metadata_conflict_422():
    repo = {
        "app": [
            c("1.0", license="MIT"),
            c("1.0", license="Apache-2.0"),
        ]
    }
    r = sbom(repo, {"app": "1.0"})
    assert r.status_code == 422
    assert "不一致" in r.json()["message"]


def test_sbom_duplicate_candidate_identical_metadata_ok():
    repo = {"app": [c("1.0", license="MIT"), c("1.0", license="MIT")]}
    body = export(repo, {"app": "1.0"})
    assert body["packages"][0]["license"] == "MIT"


# --------------------------------------------------------------------- #
# 5. 既有接口不受元数据影响
# --------------------------------------------------------------------- #
def test_metadata_ignored_by_resolve_and_audit():
    repo = full_repo()
    r = client.post("/resolve", json={
        "repository": repo,
        "root": "app",
        "target_environment": ENV,
    })
    assert r.status_code == 200, r.text
    assert r.json()["locked"] == {"app": "1.0.0", "libx": "2.0", "liby": "1.1"}

    audit = client.post("/audit-lock", json={
        "repository": repo,
        "root": "app",
        "target_environment": ENV,
        "current_lock": {"app": "1.0.0", "libx": "2.0", "liby": "1.1"},
    })
    assert audit.status_code == 200
    assert audit.json() == {"status": "ok", "valid": True, "issues": []}
