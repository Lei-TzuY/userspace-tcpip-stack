from pathlib import Path

path = Path("src/stack.rs")
text = path.read_text()
old = "self.refresh_slaac_default_router(target_ip6, 0);"
new = "self.refresh_slaac_default_router(target_ip6, 0, RouterPreference::Medium);"
if text.count(old) != 1:
    raise SystemExit(f"expected one NA Router=0 withdrawal call, found {text.count(old)}")
path.write_text(text.replace(old, new, 1))
