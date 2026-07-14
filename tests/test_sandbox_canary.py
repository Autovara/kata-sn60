"""Tests for the Layer 2 sandbox glue (source-tree renaming).

``extract_project_source`` needs Docker + a real image, so it is validated live rather
than unit-tested; ``rename_source_tree`` (the pure file walk) is covered here.
"""

from __future__ import annotations

from pathlib import Path

from kata_sn60.sandbox_canary import rename_source_tree


def test_rename_source_tree_renames_source_and_copies_the_rest(tmp_path: Path) -> None:
    src = tmp_path / "src"
    (src / "contracts").mkdir(parents=True)
    (src / "contracts" / "Staking.sol").write_text(
        "contract StakingBuffer { uint redelegateWithdrawnHYPE; }", encoding="utf-8"
    )
    (src / "README.md").write_text(
        "redelegateWithdrawnHYPE is documented here", encoding="utf-8"
    )
    dst = tmp_path / "dst"

    mapping = rename_source_tree(src, dst)

    renamed_sol = (dst / "contracts" / "Staking.sol").read_text(encoding="utf-8")
    assert "redelegateWithdrawnHYPE" not in renamed_sol  # source identifier renamed
    assert "redelegateWithdrawnHYPE" in mapping
    # Non-source files are copied verbatim (identifiers in docs are untouched).
    assert (dst / "README.md").read_text(encoding="utf-8") == (
        "redelegateWithdrawnHYPE is documented here"
    )


def test_rename_source_tree_is_consistent_across_files(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "A.sol").write_text("uint targetCollateral;", encoding="utf-8")
    (src / "B.sol").write_text("function targetCollateral() {}", encoding="utf-8")
    dst = tmp_path / "dst"

    mapping = rename_source_tree(src, dst)

    # The same identifier maps to the same replacement (per-file), so both are broken.
    assert "targetCollateral" in mapping
    assert "targetCollateral" not in (dst / "A.sol").read_text(encoding="utf-8")
    assert "targetCollateral" not in (dst / "B.sol").read_text(encoding="utf-8")
