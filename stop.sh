#!/usr/bin/env bash
# Ferma lo stack Supabase locale. I dati restano in supabase/volumes/db/data.
# (Il server FastAPI si ferma con Ctrl+C nel terminale dove gira start.sh.)
set -euo pipefail
cd "$(dirname "$0")"
echo "==> spengo i container Supabase (i dati restano persistenti)"
docker compose -f supabase/docker-compose.yml down

if docker ps -a --format '{{.Names}}' | grep -q '^vuln-test-linux-1$'; then
  echo "==> stop e rimozione container di test vuln-test-linux-1"
  docker rm -f vuln-test-linux-1
fi

if docker ps -a --format '{{.Names}}' | grep -q '^vuln-test-windows-1$'; then
  echo "==> stop e rimozione container di test vuln-test-windows-1"
  docker rm -f vuln-test-windows-1
fi

echo "==> fatto. Riavvio: ./start.sh"
