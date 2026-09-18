"""SBOM 清单导出（POST /sbom）：沿已激活依赖图生成确定性 JSON 清单。

调用本模块前，``current_lock`` 已由 :func:`app.audit.audit_lock` 判定为
**有效**（与 /dependency-paths 相同的前置条件），因此这里不做任何版本
选择与约束核对：按锁定版本在目标环境下已激活的依赖建图，为锁中每个包
输出一行清单——规范化包名、锁定版本、PURL、直接依赖的规范化名称，以及
仓库快照中该版本携带的元数据（``source_url`` / ``sha256`` / ``license``）。

* 包按规范化包名排序，依赖名列表同样排序；输出与包键、候选列表、锁键的
  输入顺序无关（同一输入逐字节一致）；
* PURL 采用 pypi 类型：``pkg:pypi/<规范化名>@<锁定版本>``（包名已按
  PEP 503 规范化，版本为锁中 PEP 440 文本）；
* 元数据缺失（快照未携带或为空白）**不阻断导出**：对应字段输出 ``null``，
  并在 ``warnings`` 中按 (包名, 字段) 顺序各记一条。
"""

from __future__ import annotations

from packaging.version import Version

from .audit import _find_candidate
from .paths import build_locked_graph
from .repository import METADATA_FIELDS, Repository


def build_sbom(
    repo: Repository,
    *,
    root_name: str,
    current_lock: dict[str, Version],
) -> dict:
    """在有效锁上生成 SBOM：``{"packages": [...], "warnings": [...]}``。

    ``packages`` 按规范化包名排序；``warnings`` 按（包名, 字段声明顺序）
    排列，二者均与输入顺序无关。
    """
    graph = build_locked_graph(repo, root_name=root_name, current_lock=current_lock)

    packages: list[dict] = []
    warnings: list[dict] = []
    for name in sorted(graph):
        locked = current_lock[name]  # 有效锁：可达包必有锁定版本
        cand = _find_candidate(repo, name, locked)
        assert cand is not None  # 有效锁：锁定版本必在快照中
        entry: dict = {
            "name": name,
            "version": str(locked),
            "purl": f"pkg:pypi/{name}@{locked}",
            "dependencies": graph[name],
        }
        for field_name in METADATA_FIELDS:
            value = cand.metadata[field_name]
            entry[field_name] = value
            if value is None:
                warnings.append(
                    {
                        "package": name,
                        "field": field_name,
                        "message": (
                            f"包 {name}=={locked} 缺少元数据字段 {field_name}"
                        ),
                    }
                )
        packages.append(entry)

    return {"packages": packages, "warnings": warnings}
