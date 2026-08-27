#!/usr/bin/env bash
set -euo pipefail

git fetch origin feat/ipv6-ra-mtu-option

git show origin/feat/ipv6-ra-mtu-option:scripts/one-shot-ra-mtu.sh > /tmp/one-shot-ra-mtu.sh
python3 - <<'PY'
from pathlib import Path
p = Path('/tmp/one-shot-ra-mtu.sh')
s = p.read_text()
s = s.replace('    assert_ne!(ns_eth.ethertype, 0);\n', '    assert_eq!(ns_eth.ethertype, toy_tcpip::ethernet::EtherType::Ipv6);\n')
s = s.replace('rm .github/workflows/one-shot-ra-mtu.yml scripts/one-shot-ra-mtu.sh\n', 'rm .github/workflows/one-shot-ra-mtu-v2.yml scripts/one-shot-ra-mtu-v2.sh\n')
s = s.replace('git push origin HEAD:feat/ipv6-ra-mtu-option\n', 'git push origin HEAD:feat/ipv6-ra-mtu-option-v2\n')
p.write_text(s)
PY
bash /tmp/one-shot-ra-mtu.sh
