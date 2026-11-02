#!/usr/bin/env python3
"""Exercise malformed/nonminimal envelopes using the unchanged pinned Swift codec."""
from pathlib import Path
import json
import subprocess
import tempfile
import sys
import hashlib
ROOT = Path(__file__).resolve().parents[1]
upstream = Path(sys.argv[1]).resolve()
revision = json.loads((ROOT / 'upstream-lock.json').read_text())['Multikey']
assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=upstream, text=True).strip() == revision
assert not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=upstream)
inputs = ['', 'e', 'zz', 'é', '0Xed01', ' ed01', 'ed01\n', '0xed01', 'ED01',
          'ed+1', 'ed-0', 'ed01+1', 'ed01-0', 'ed01-1', 'ed01éé', 'ed01１２', 'ed01١٢']
for last in range(256):
    inputs.append(bytes([0xed, 0x81] + [0x80] * 7 + [last]).hex())
for length in range(1, 13):
    inputs.extend([bytes([0x80] * length).hex(), bytes([0xed] + [0x80] * length + [0]).hex()])
inputs = list(dict.fromkeys(inputs))
with tempfile.TemporaryDirectory(prefix='multikey-malformed-') as tmp:
    tmp = Path(tmp)
    (tmp / 'inputs.json').write_text(json.dumps(inputs))
    (tmp / 'main.swift').write_text('''import Foundation
let inputs = try JSONDecoder().decode([String].self, from: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1])))
for text in inputs {
    let result: String
    do { result = try Multikey.decode(fromHex: text).hexEncoded }
    catch { result = "error:" + String(describing: error) }
    let bytes = try JSONSerialization.data(withJSONObject: ["input": text, "result": result], options: [.sortedKeys])
    print(String(decoding: bytes, as: UTF8.self))
}
''')
    sources = sorted((upstream / 'Sources/Multikey').glob('*.swift'))
    subprocess.run(['swiftc', *map(str, sources), str(tmp / 'main.swift'), '-o', str(tmp / 'oracle')], check=True)
    data = subprocess.check_output([str(tmp / 'oracle'), str(tmp / 'inputs.json')], text=True)
    rows = [json.loads(line) for line in data.splitlines()]
    path = ROOT / 'tests/swift-malformed.json'
    path.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + '\n')
    (ROOT / 'tests/swift-malformed-provenance.json').write_text(json.dumps(dict(revision=revision, cases=len(rows), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), sources={str(p.relative_to(upstream)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}), indent=2) + '\n')
    print(f'{len(rows)} Swift cases')
    for row in rows[:17]: print(row)
