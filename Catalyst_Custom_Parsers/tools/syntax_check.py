"""TextFSM lightweight regex/fixture sanity check, NOT a TextFSM runtime replacement."""
from pathlib import Path
import re
ROOT=Path(__file__).resolve().parents[1]
count=0
for p in (ROOT/'TextFSM').glob('*.textfsm'):
    lines=p.read_text(encoding='utf8').splitlines()
    definitions={}
    state=None; regexes=[]
    for line in lines:
        m=re.match(r'^Value\s+(?:(?:Filldown|Required|Fillup|List|Key)\s+)*([A-Z_]+)\s+(\(.+\))$',line)
        if m:
            definitions[m.group(1)]=m.group(2)
        elif line.startswith('  ^'):
            pattern=line.strip().split(' -> ')[0]
            pattern=re.sub(r'\$\{([A-Z_]+)\}',lambda m:definitions[m.group(1)],pattern)
            pattern=pattern.replace('$$','$')
            regexes.append(re.compile(pattern))
    fixture=ROOT/'fixtures'/(p.stem.removeprefix('cisco_ios_')+'.txt')
    if not fixture.exists(): raise SystemExit(f'Fixture missing {fixture.name}')
    hits=[line for line in fixture.read_text(encoding='utf8').splitlines() if any(rx.match(line) for rx in regexes)]
    if len(hits)<1: raise SystemExit(f'No matches: {p.name}')
    print(f'REGEX OK {p.name}: {len(hits)} fixture line matches')
    count+=1
print(f'PASS: {count} template regex sets compile and recognize fixture lines.')
print('NOTE: Use tools/parse_custom.py --test-all with textfsm + ttp installed for engine-level testing.')
