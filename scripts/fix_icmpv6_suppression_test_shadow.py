from pathlib import Path

path = Path("tests/test_ipv6_icmp_error_suppression.rs")
text = path.read_text()
if text.count("fn router() -> LabRouter") != 1:
    raise SystemExit("unexpected router factory count")
if text.count("let mut router = router();") < 1:
    raise SystemExit("expected router factory calls")
text = text.replace("fn router() -> LabRouter", "fn make_router() -> LabRouter", 1)
text = text.replace("let mut router = router();", "let mut router = make_router();")
path.write_text(text)
