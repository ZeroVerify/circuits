#!/usr/bin/env bash
set -Eeuo pipefail

#this is the test run to make sure everything works
DRY_RUN="${DRY_RUN:-false}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
CIRCUIT_SRC_DIR="${ROOT_DIR}/circuit_files"
PTAU_DIR="${ROOT_DIR}/ptau"

# Required in normal mode
if [[ "${DRY_RUN}" == "false" ]]; then
  : "${S3_BUCKET:?S3_BUCKET is required}"
  : "${AWS_REGION:?AWS_REGION is required}"
fi

# Required always
: "${BEACON_HASH:?BEACON_HASH is required (64 hex chars, no 0x prefix)}"

# Optional with defaults
: "${CEREMONY_NAME:=ZeroVerify trusted setup}"
: "${BEACON_ROUNDS:=10}"
: "${CIRCUITS:=student_status}"
: "${ZKEY_ENTROPY:=$(openssl rand -hex 32)}"
: "${CIRCOMLIB_PATH:=/home/simon/node_modules/circomlib/circuits}"

mkdir -p "${BUILD_DIR}" "${PTAU_DIR}"

log() {
  echo
  echo "==> $*"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

mime_type_for() {
  case "$1" in
    *.json) echo "application/json" ;;
    *.wasm) echo "application/wasm" ;;
    *.zkey) echo "application/octet-stream" ;;
    *) echo "application/octet-stream" ;;
  esac
}

upload_artifact() {
  local file="$1"
  local s3_key="$2"
  local content_type
  content_type="$(mime_type_for "$file")"

  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "[DRY RUN] Would upload: ${file} -> s3://${S3_BUCKET:-dummy-bucket}/${s3_key}"
    echo "[DRY RUN] Headers: Content-Type=${content_type}, Cache-Control=public, max-age=86400"
    return 0
  fi

  aws s3 cp "${file}" "s3://${S3_BUCKET}/${s3_key}" \
    --region "${AWS_REGION}" \
    --content-type "${content_type}" \
    --cache-control "public, max-age=86400"
}

verify_public_url() {
  local url="$1"

  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "[DRY RUN] Would verify public URL: ${url}"
    return 0
  fi

  curl -fsI "${url}" >/dev/null
}

download_ptau_if_needed() {
  local ptau_file="$1"
  local ptau_url="$2"

  if [[ -f "${ptau_file}" ]]; then
    log "Using existing PTAU: ${ptau_file}"
    return 0
  fi

  log "Downloading PTAU: ${ptau_url}"
  curl -fL "${ptau_url}" -o "${ptau_file}"
}

# Adjust these thresholds later if your circuits get bigger.
select_ptau_for_constraints() {
  local constraints="$1"

  if (( constraints <= 65536 )); then
    echo "powersOfTau28_hez_final_16.ptau|https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_16.ptau"
  elif (( constraints <= 131072 )); then
    echo "powersOfTau28_hez_final_17.ptau|https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_17.ptau"
  elif (( constraints <= 262144 )); then
    echo "powersOfTau28_hez_final_18.ptau|https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_18.ptau"
  else
    echo "Constraint count ${constraints} too large" >&2
    exit 1
  fi
}

extract_constraints() {
  local r1cs_file="$1"
  local info
  info="$(snarkjs r1cs info "${r1cs_file}")"

  local constraints
  constraints="$(printf '%s\n' "${info}" | sed -nE 's/.*# of Constraints: *([0-9]+).*/\1/p')"

  if [[ -z "${constraints}" ]]; then
    echo "Could not parse constraint count from snarkjs r1cs info output." >&2
    printf '%s\n' "${info}" >&2
    exit 1
  fi

  echo "${constraints}"
}

run_fullprove_sanity_test() {
  local proof_type="$1"
  local wasm_file="$2"
  local zkey_file="$3"
  local vkey_file="$4"

  local input_file=""
  if [[ -f "${ROOT_DIR}/testdata/${proof_type}/input_valid.json" ]]; then
    input_file="${ROOT_DIR}/testdata/${proof_type}/input_valid.json"
  else
    log "No valid test input found for ${proof_type}; skipping fullProve sanity test"
    return 0
  fi

  local proof_file="${BUILD_DIR}/${proof_type}/proof.json"
  local public_file="${BUILD_DIR}/${proof_type}/public.json"

  log "Running fullProve sanity test for ${proof_type}"
  snarkjs groth16 fullprove \
    "${input_file}" \
    "${wasm_file}" \
    "${zkey_file}" \
    "${proof_file}" \
    "${public_file}"

  log "Verifying proof for ${proof_type}"
  snarkjs groth16 verify \
    "${vkey_file}" \
    "${public_file}" \
    "${proof_file}"
}

process_circuit() {
  local proof_type="$1"
  local circuit_file="${CIRCUIT_SRC_DIR}/${proof_type}.circom"
  local out_dir="${BUILD_DIR}/${proof_type}"

  if [[ ! -f "${circuit_file}" ]]; then
    echo "Required circuit file not found: ${circuit_file}" >&2
    exit 1
  fi

  mkdir -p "${out_dir}"

  log "Compiling ${proof_type}"
  circom "${circuit_file}" \
    --r1cs --wasm --sym \
    -o "${out_dir}" \
    -l "${CIRCOMLIB_PATH}"

  local r1cs_file="${out_dir}/${proof_type}.r1cs"
  local wasm_file="${out_dir}/${proof_type}_js/${proof_type}.wasm"
  local zkey_0="${out_dir}/proving_key_0000.zkey"
  local zkey_1="${out_dir}/proving_key_0001.zkey"
  local final_zkey="${out_dir}/proving_key.zkey"
  local vkey_file="${out_dir}/verification_key.json"

  if [[ ! -f "${r1cs_file}" ]]; then
    echo "Expected R1CS file not found: ${r1cs_file}" >&2
    exit 1
  fi

  if [[ ! -f "${wasm_file}" ]]; then
    echo "Expected WASM file not found: ${wasm_file}" >&2
    exit 1
  fi

  log "Reading constraint count for ${proof_type}"
  local constraints
  constraints="$(extract_constraints "${r1cs_file}")"
  echo "Constraints for ${proof_type}: ${constraints}"

  local ptau_meta
  ptau_meta="$(select_ptau_for_constraints "${constraints}")"

  local ptau_name="${ptau_meta%%|*}"
  local ptau_url="${ptau_meta##*|}"
  local ptau_file="${PTAU_DIR}/${ptau_name}"

  download_ptau_if_needed "${ptau_file}" "${ptau_url}"

  log "Running groth16 setup for ${proof_type}"
  snarkjs groth16 setup "${r1cs_file}" "${ptau_file}" "${zkey_0}"

  log "Running zkey contribute for ${proof_type}"
  snarkjs zkey contribute \
    "${zkey_0}" \
    "${zkey_1}" \
    --name="${CEREMONY_NAME}" \
    -e="${ZKEY_ENTROPY}" \
    -v

  log "Running zkey beacon for ${proof_type}"
  snarkjs zkey beacon \
    "${zkey_1}" \
    "${final_zkey}" \
    "${BEACON_HASH}" \
    "${BEACON_ROUNDS}" \
    -n="Final Beacon"

  log "Exporting verification key for ${proof_type}"
  snarkjs zkey export verificationkey "${final_zkey}" "${vkey_file}"

  run_fullprove_sanity_test "${proof_type}" "${wasm_file}" "${final_zkey}" "${vkey_file}"

  local s3_prefix="circuit/${proof_type}"
  upload_artifact "${final_zkey}" "${s3_prefix}/proving_key.zkey"
  upload_artifact "${wasm_file}" "${s3_prefix}/circuit.wasm"
  upload_artifact "${vkey_file}" "${s3_prefix}/verification_key.json"

  if [[ "${DRY_RUN}" != "true" ]]; then
    local base_url="https://${S3_BUCKET}.s3.${AWS_REGION}.amazonaws.com/${s3_prefix}"
    verify_public_url "${base_url}/proving_key.zkey"
    verify_public_url "${base_url}/circuit.wasm"
    verify_public_url "${base_url}/verification_key.json"
    log "Verified public artifact URLs for ${proof_type}"
  fi
}

main() {
  need_cmd circom
  need_cmd snarkjs
  need_cmd curl
  need_cmd openssl

  if [[ "${DRY_RUN}" == "false" ]]; then
    need_cmd aws
  fi

  if [[ ! -d "${CIRCOMLIB_PATH}" ]]; then
    echo "circomlib include path not found: ${CIRCOMLIB_PATH}" >&2
    echo "Set CIRCOMLIB_PATH to the directory containing poseidon.circom, eddsa.circom, and comparators.circom" >&2
    exit 1
  fi
  
  for proof_type in ${CIRCUITS}; do
    process_circuit "${proof_type}"
  done

  log "Trusted setup completed successfully"
}

main "$@"