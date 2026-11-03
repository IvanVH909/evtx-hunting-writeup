#!/usr/bin/env bash
# Descarga lo necesario en ./lab (no se sube a git): muestras EVTX, reglas Sigma y Chainsaw (Linux x86_64).
# Para macOS/Windows descarga el binario correspondiente desde la pagina de releases de Chainsaw.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p lab && cd lab

CHAINSAW_VERSION="v2.17.1"

[ -d evtx ]  || git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git evtx
[ -d sigma ] || { git clone --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git sigma \
                  && (cd sigma && git sparse-checkout set rules/windows); }
if [ ! -d chainsaw ]; then
  curl -sL -o chainsaw.zip "https://github.com/WithSecureOpenSource/chainsaw/releases/download/${CHAINSAW_VERSION}/chainsaw_all_platforms+rules.zip"
  unzip -q chainsaw.zip && rm chainsaw.zip
  chmod +x chainsaw/chainsaw_x86_64-unknown-linux-gnu
fi
echo "Listo. Ahora ejecuta: scripts/run_hunt.sh"
