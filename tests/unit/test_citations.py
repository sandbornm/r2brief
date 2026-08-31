from r2b.llm.citations import (
    format_cite,
    parse_cited_claims,
    parse_cites,
    proposed_annotations_from_claims,
)
from r2b.llm.prompts import ANALYST_SYSTEM, PROMPT_ID, REGION_ASK_RULES


def test_prompt_requires_cites_and_proposed_names() -> None:
    assert PROMPT_ID == "r2b.prompt.v2"
    assert "cite tag" in ANALYST_SYSTEM
    assert "proposed" in ANALYST_SYSTEM.lower()
    assert any("cite" in rule.lower() for rule in REGION_ASK_RULES)


def test_parse_cited_claims_splits_grounded_and_uncited() -> None:
    text = """
- strcpy at entry is attacker-controlled [tool=radare2 addr=0x7a8 artifact=imports:plt xref=strcpy]
- proposed name http_auth for sub_401000 [tool=radare2 addr=0x401000 xref=strcmp]
- this has no cite and should be uncited as a claim
4. r2b brief child.elf --quick [tool=artifact_dag addr=0x1198d9 artifact=n:elf:abcd xref=httpd]
"""
    parsed = parse_cited_claims(text)
    assert parsed["schema_version"] == "r2b.cited_claims.v1"
    assert len(parsed["claims"]) == 3
    assert parsed["claims"][0]["cites"][0]["tool"] == "radare2"
    assert parsed["claims"][0]["cites"][0]["addr"] == "0x7a8"
    assert parsed["proposed"]
    assert any("no cite" in line for line in parsed["uncited"])
    assert not parsed["grounded"]


def test_format_cite_roundtrip() -> None:
    tag = format_cite(tool="ghidra", addr="0x8000", artifact="n:elf:ab", xref="main")
    cites = parse_cites(f"claim {tag}")
    assert cites == [{"tool": "ghidra", "addr": "0x8000", "artifact": "n:elf:ab", "xref": "main"}]


def test_proposed_annotations_from_claims_keeps_only_invented_names() -> None:
    cited = parse_cited_claims(
        """
- strcpy at entry is attacker-controlled [tool=radare2 addr=0x7a8 artifact=imports:plt xref=strcpy]
- proposed name http_auth for sub_401000 [tool=radare2 addr=0x401000 xref=strcmp]
"""
    )
    rows = proposed_annotations_from_claims(cited)
    assert len(rows) == 1
    assert rows[0]["kind"] == "name"
    assert rows[0]["status"] == "proposed"
    assert rows[0]["address"] == "0x401000"
    assert rows[0]["xref"] == "strcmp"
