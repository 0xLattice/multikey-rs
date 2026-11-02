#!/usr/bin/env python3
"""Generate encode/decode vectors using the pinned, unmodified Swift Multikey."""
from pathlib import Path
import json, subprocess, sys, tempfile
repo = Path(__file__).resolve().parents[1]
upstream = Path(sys.argv[1]).resolve()
lock = json.loads((repo / 'upstream-lock.json').read_text())
sha = subprocess.check_output(['git','-C',str(upstream),'rev-parse','HEAD'],text=True).strip()
assert sha == lock['Multikey'], 'upstream revision changed'
with tempfile.TemporaryDirectory(prefix='multikey-oracle-') as tmp:
    main = Path(tmp) / 'main.swift'
    main.write_text('''import Foundation
for kind in KeyType.allCases {
    for size in [0, 1, 32, 65, 1312, 2592] {
        let bytes = Data((0..<size).map { UInt8($0 % 256) })
        let key = Multikey(keyType: kind, keyBytes: bytes)
        let hex = key.hexEncoded
        let decoded = try Multikey.decode(fromHex: hex)
        precondition(decoded == key)
        print(String(kind.rawValue) + " " + hex)
    }
}
''')
    binary = str(Path(tmp) / 'oracle')
    sources = [str(p) for p in (upstream/'Sources/Multikey').glob('*.swift')]
    subprocess.run(['swiftc', *sources, str(main), '-o', binary], check=True)
    output = subprocess.check_output([binary], text=True)
    (repo/'tests/swift-vectors.txt').write_text(output)
    print(f'Wrote {len(output.splitlines())} Swift vectors')
