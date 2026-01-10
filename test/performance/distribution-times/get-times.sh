#!/usr/bin/env bash
set -euo pipefail

# para activar alias de microk8s kubectl en bash
shopt -s expand_aliases
alias kubectl='microk8s kubectl'

# =======================
# Configuración
# =======================
KUBECONFIG_PATH="../../../microk8s-site1-kubeconfig.yaml"
NAMESPACE="${NAMESPACE:-default}"

# Nº de sec-agents (iterator)
N_AGENTS="${N_AGENTS:-4}"

MANAGER_RELEASE="${MANAGER_RELEASE:-nfvsec-manager}"
MANAGER_CHART="${MANAGER_CHART:-../../../charts/nfvsec-manager}"

AGENTS_RELEASE="sec-agents-${N_AGENTS}"
AGENTS_CHART="${AGENTS_CHART:-../../../charts/sec-agent-eval}"

# Nº de repeticiones
REPEATS="${REPEATS:-20}"

WAIT_AFTER_INSTALL_SEC="${WAIT_AFTER_INSTALL_SEC:-15}"
WAIT_AFTER_TRIGGER_SEC="${WAIT_AFTER_TRIGGER_SEC:-60}"

# Endpoint del manager (AJUSTA si cambia)
TOPOLOGY_URL="${TOPOLOGY_URL:-http://10.4.16.35:8000/topology}"

# VL id
VL_ID="${VL_ID:-ns_001.vl_001}"

# Marker en logs del manager para inicio de medida
MANAGER_MARKER_REGEX="${MANAGER_MARKER_REGEX:-Topology published successfully}"

# Marker en logs del sec-agent para medir "negociación"
AGENT_NEGOTIATION_MARKER_REGEX="${AGENT_NEGOTIATION_MARKER_REGEX:-Configuring MACsec for}"

OUTDIR="${OUTDIR:-./results}"
CSV_OUT="${OUTDIR}/distribution_times_${N_AGENTS}_agents.csv"

mkdir -p "${OUTDIR}"

log() { echo "[$(date +"%Y-%m-%d %H:%M:%S")] $*"; }

# =======================
# Extraer timestamp de log
# =======================
# Extrae "YYYY-MM-DD HH:MM:SS,mmm" de una línea tipo:
# [2026-01-08 15:09:54,818] [INFO] ...
extract_ts_from_line() {
  sed -n 's/^\[\([0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\},[0-9]\{3\}\)\].*$/\1/p'
}

# =======================
# Generación dinámica del JSON /topology
# =======================
generate_topology_json() {
  local n_agents="$1"
  local vl_id="$2"

  echo '['
  echo '  {'
  echo "    \"vl_id\": \"${vl_id}\","
  echo '    "neighbours": ['

  for i in $(seq 1 "${n_agents}"); do
    echo '      {'
    echo "        \"vnf_id\": \"VNF_SECAGENT_${i}\","
    echo '        "interface": "net1",'
    echo "        \"publickey\": \"vnfsec-PKEY-${i}\""
    if [[ "${i}" -lt "${n_agents}" ]]; then
      echo '      },'
    else
      echo '      }'
    fi
  done

  echo '    ]'
  echo '  }'
  echo ']'
}

do_trigger() {
  local json
  json="$(generate_topology_json "${N_AGENTS}" "${VL_ID}")"

  log "Trigger HTTP POST ${TOPOLOGY_URL} (N_AGENTS=${N_AGENTS}, VL_ID=${VL_ID})"
  echo "----- TOPOLOGY JSON BEGIN -----"
  echo "${json}"
  echo "----- TOPOLOGY JSON END -----"

  # Validación opcional con jq si existe
  if command -v jq >/dev/null 2>&1; then
    echo "${json}" | jq . >/dev/null
  fi

  # Mostramos respuesta del server
  curl -sS -X POST "${TOPOLOGY_URL}" \
    -H "Content-Type: application/json" \
    -d "${json}"
  echo
}

# =======================
# Kubernetes / Helm helpers
# =======================
helm_uninstall_if_exists() {
  local rel="$1"
  if helm status "${rel}" --kubeconfig "${KUBECONFIG_PATH}" -n "${NAMESPACE}" >/dev/null 2>&1; then
    log "helm uninstall ${rel}"
    helm uninstall "${rel}" --kubeconfig "${KUBECONFIG_PATH}" -n "${NAMESPACE}" >/dev/null
  fi
}

wait_pods_gone_by_prefix() {
  local prefix="$1"
  local timeout_sec="${2:-60}"
  local start
  start="$(date +%s)"

  while true; do
    if ! kubectl --kubeconfig "${KUBECONFIG_PATH}" -n "${NAMESPACE}" get pods 2>/dev/null \
      | awk 'NR>1{print $1}' | grep -q "^${prefix}"; then
      return 0
    fi
    if (( $(date +%s) - start > timeout_sec )); then
      log "WARN: timeout esperando borrar pods con prefijo ${prefix}"
      return 0
    fi
    sleep 2
  done
}

get_manager_pod_name() {
  # Asume que el pod del manager empieza por "security-manager-"
  kubectl --kubeconfig "${KUBECONFIG_PATH}" -n "${NAMESPACE}" get pods \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' \
    | grep '^security-manager-' | head -n 1
}

get_agent_pod_name() {
  local i="$1"
  echo "sec-agent-${i}"
}


# =======================
# Extracción de timestamps de sec-agents
# =======================

# Último timestamp presente en el log del pod (para "total")
get_last_ts_from_pod_logs() {
  local pod="$1"
  kubectl --kubeconfig "${KUBECONFIG_PATH}" -n "${NAMESPACE}" logs "${pod}" 2>/dev/null \
    | awk '
        match($0, /^\[[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3}\]/) {
          ts=substr($0,2,23)
        }
        END { if (ts!="") print ts }
      '
}

# Último timestamp de una línea que contenga un marker (para "negociación")
get_last_ts_matching_from_pod_logs() {
  local pod="$1"
  local pattern="$2"

  kubectl --kubeconfig "${KUBECONFIG_PATH}" -n "${NAMESPACE}" logs "${pod}" 2>/dev/null \
    | awk -v pat="$pattern" '
        $0 ~ pat && match($0, /^\[[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3}\]/) {
          ts=substr($0,2,23)
        }
        END { if (ts!="") print ts }
      '
}

# =======================
# Cálculo de diferencia con Python (portable macOS)
# =======================
calc_duration_ms() {
  local manager_ts="$1"
  local end_ts="$2"

  python3 - <<'PY' "${manager_ts}" "${end_ts}"
import sys
from datetime import datetime, timezone

m = sys.argv[1]
e = sys.argv[2]
fmt = "%Y-%m-%d %H:%M:%S,%f"

tm = datetime.strptime(m, fmt).replace(tzinfo=timezone.utc)
te = datetime.strptime(e, fmt).replace(tzinfo=timezone.utc)
print(int((te - tm).total_seconds() * 1000))
PY
}

# =======================
# Cleanup on exit (always)
# =======================
cleanup() {
  log "Cleanup: uninstalling Helm releases"

  helm_uninstall_if_exists "${AGENTS_RELEASE}" || true
  helm_uninstall_if_exists "${MANAGER_RELEASE}" || true

  # Best-effort wait for pods to disappear
  wait_pods_gone_by_prefix "sec-agent-" 90 || true
  wait_pods_gone_by_prefix "security-manager-" 90 || true

  log "Cleanup completed"
}

# Ensure cleanup runs on normal exit, error, or Ctrl+C
trap cleanup EXIT INT TERM


# =======================
# CSV header (separator ;)
# =======================
if [[ ! -f "${CSV_OUT}" ]]; then
  echo "run;n_agents;manager_ts_utc;agent_neg_max_ts_utc;negotiation_ms;agent_last_max_ts_utc;total_ms" > "${CSV_OUT}"
fi

# =======================
# Loop principal
# =======================
for run in $(seq 1 "${REPEATS}"); do
  log "================ RUN ${run}/${REPEATS} (N_AGENTS=${N_AGENTS}) ================"

  # Limpieza
  helm_uninstall_if_exists "${AGENTS_RELEASE}"
  helm_uninstall_if_exists "${MANAGER_RELEASE}"

  # Espera a que desaparezcan pods antiguos
  wait_pods_gone_by_prefix "sec-agent-" 90
  wait_pods_gone_by_prefix "security-manager-" 90

  # Instala manager
  log "helm install ${MANAGER_RELEASE} ${MANAGER_CHART}"
  helm install "${MANAGER_RELEASE}" "${MANAGER_CHART}" \
    --kubeconfig "${KUBECONFIG_PATH}" -n "${NAMESPACE}" >/dev/null

  log "Esperando ${WAIT_AFTER_INSTALL_SEC}s tras instalar el manager..."
  sleep "${WAIT_AFTER_INSTALL_SEC}"

  # Instala agentes con iterator=N_AGENTS
  log "helm install ${AGENTS_RELEASE} ${AGENTS_CHART} --set iterator=${N_AGENTS}"
  helm install "${AGENTS_RELEASE}" "${AGENTS_CHART}" \
    --set "iterator=${N_AGENTS}" \
    --kubeconfig "${KUBECONFIG_PATH}" -n "${NAMESPACE}" >/dev/null

  log "Esperando ${WAIT_AFTER_INSTALL_SEC}s tras instalar los agentes..."
  sleep "${WAIT_AFTER_INSTALL_SEC}"

  # Trigger HTTP (imprime JSON)
  do_trigger

  log "Esperando ${WAIT_AFTER_TRIGGER_SEC}s para que termine el proceso..."
  sleep "${WAIT_AFTER_TRIGGER_SEC}"

  # Pod del manager
  manager_pod="$(get_manager_pod_name || true)"
  if [[ -z "${manager_pod}" ]]; then
    log "ERROR: No pude detectar el pod del manager (prefijo security-manager-)."
    echo "${run};${N_AGENTS};NA;NA;NA;NA;NA" >> "${CSV_OUT}"
    continue
  fi
  log "Manager pod: ${manager_pod}"

  # Timestamp del manager: primera línea con el marker
  manager_line="$(
    kubectl --kubeconfig "${KUBECONFIG_PATH}" -n "${NAMESPACE}" logs "${manager_pod}" 2>/dev/null \
      | grep -m1 "${MANAGER_MARKER_REGEX}" || true
  )"

  if [[ -z "${manager_line}" ]]; then
    log "ERROR: No encontré el marker en logs del manager: ${MANAGER_MARKER_REGEX}"
    echo "${run};${N_AGENTS};NA;NA;NA;NA;NA" >> "${CSV_OUT}"
    continue
  fi

  manager_ts="$(echo "${manager_line}" | extract_ts_from_line || true)"
  if [[ -z "${manager_ts}" ]]; then
    log "ERROR: No pude extraer timestamp del manager en: ${manager_line}"
    echo "${run};${N_AGENTS};NA;NA;NA;NA;NA" >> "${CSV_OUT}"
    continue
  fi

  # Obtener el timestamp más tardío entre agentes para:
  # 1) negociación: marker "Configuring MACsec for"
  # 2) total: último timestamp del log
  neg_max_ts=""
  total_max_ts=""

  for i in $(seq 1 "${N_AGENTS}"); do
    pod="$(get_agent_pod_name "${i}")"

    # Negotiation marker timestamp (per pod)
    neg_ts="$(get_last_ts_matching_from_pod_logs "${pod}" "${AGENT_NEGOTIATION_MARKER_REGEX}" || true)"
    if [[ -z "${neg_ts}" ]]; then
      log "WARN: No pude extraer timestamp (negotiation marker) de ${pod} con patrón: ${AGENT_NEGOTIATION_MARKER_REGEX}"
    else
      if [[ -z "${neg_max_ts}" || "${neg_ts}" > "${neg_max_ts}" ]]; then
        neg_max_ts="${neg_ts}"
      fi
    fi

    # Total end timestamp (per pod)
    end_ts="$(get_last_ts_from_pod_logs "${pod}" || true)"
    if [[ -z "${end_ts}" ]]; then
      log "WARN: No pude extraer último timestamp de ${pod}"
    else
      if [[ -z "${total_max_ts}" || "${end_ts}" > "${total_max_ts}" ]]; then
        total_max_ts="${end_ts}"
      fi
    fi
  done

  negotiation_ms="NA"
  total_ms="NA"

  if [[ -n "${neg_max_ts}" ]]; then
    negotiation_ms="$(calc_duration_ms "${manager_ts}" "${neg_max_ts}")"
  else
    log "ERROR: No pude obtener ningún timestamp de negociación (marker) de los agentes."
  fi

  if [[ -n "${total_max_ts}" ]]; then
    total_ms="$(calc_duration_ms "${manager_ts}" "${total_max_ts}")"
  else
    log "ERROR: No pude obtener ningún timestamp final (último log) de los agentes."
  fi

  log "Manager marker: ${manager_ts}"
  log "Negotiation end (max across agents): ${neg_max_ts:-NA} | negotiation_ms: ${negotiation_ms}"
  log "Total end (max across agents):       ${total_max_ts:-NA} | total_ms:       ${total_ms}"

  echo "${run};${N_AGENTS};${manager_ts};${neg_max_ts:-NA};${negotiation_ms};${total_max_ts:-NA};${total_ms}" >> "${CSV_OUT}"
done

log "Terminado. CSV: ${CSV_OUT}"
