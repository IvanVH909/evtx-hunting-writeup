#!/usr/bin/env python3
"""Resume la salida JSONL de Chainsaw en tablas Markdown (reglas mas frecuentes y ficheros con mas detecciones)."""
import json
import sys
from collections import Counter, defaultdict


def main(path: str) -> None:
    rows = [json.loads(line) for line in open(path, encoding="utf-8")]
    by_rule = Counter((r["name"], r["level"]) for r in rows)
    techniques = defaultdict(set)
    for r in rows:
        techniques[r["name"]].update(t.replace("attack.", "").upper() for t in r.get("tags", []) if t.startswith("attack.t"))
    by_file = Counter(r["document"]["path"].split("evtx/", 1)[-1] for r in rows)

    print(f"# Resumen de detecciones\n\nTotal de detecciones high/critical: **{len(rows)}** "
          f"en **{len(by_file)}** ficheros EVTX.\n")
    print("## Reglas mas frecuentes\n")
    print("| Regla | Severidad | Detecciones | Tecnicas ATT&CK |")
    print("|---|---|---|---|")
    for (name, level), n in by_rule.most_common(15):
        print(f"| {name} | {level} | {n} | {', '.join(sorted(techniques[name])) or '-'} |")
    print("\n## Ficheros con mas detecciones\n")
    print("| Fichero | Detecciones |")
    print("|---|---|")
    for f, n in by_file.most_common(10):
        print(f"| `{f}` | {n} |")


if __name__ == "__main__":
    main(sys.argv[1])
