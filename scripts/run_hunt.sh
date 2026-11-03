#!/usr/bin/env bash
# Ejecuta Chainsaw con reglas Sigma + reglas propias de Chainsaw sobre todas las muestras
# y guarda las detecciones HIGH/CRITICAL en results/hunt.jsonl
set -euo pipefail
cd "$(dirname "$0")/../lab"
mkdir -p ../results
./chainsaw/chainsaw_x86_64-unknown-linux-gnu hunt evtx/ \
  -s sigma/rules/windows \
  -r chainsaw/rules \
  --mapping chainsaw/mappings/sigma-event-logs-all.yml \
  --level high --level critical \
  --skip-errors --jsonl -q -o ../results/hunt.jsonl
echo "Detecciones guardadas en results/hunt.jsonl"
python3 ../scripts/summarize_hunt.py ../results/hunt.jsonl > ../results/resumen.md
echo "Resumen en results/resumen.md"
