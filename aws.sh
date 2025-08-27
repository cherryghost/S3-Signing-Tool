set -euo pipefail

# ============================================================
# Generic AWS Signature V4 cURL helper for ANY S3-compatible host
# ============================================================

# -------- Inputs --------
read -p "Enter Access Key ID: " AWS_ACCESS_KEY_ID
read -s -p "Enter Secret Access Key: " AWS_SECRET_ACCESS_KEY; echo

read -p "SigV4 Region [eu-central-1]: " AWS_REGION
AWS_REGION="${AWS_REGION:-eu-central-1}"

read -p "Enter FULL host or URL (Any S3 compatible host): " INPUT_HOST
read -p "HTTP Method [GET]: " HTTP_REQUEST_METHOD
HTTP_REQUEST_METHOD="${HTTP_REQUEST_METHOD:-GET}"

read -p "Enter Canonical Request URI (start with /, e.g. / or /path/to/object): " HTTP_CANONICAL_REQUEST_URI
read -p "Optional Query String (e.g. list-type=2&prefix=wp/) [blank for none]: " HTTP_CANONICAL_REQUEST_QUERY_STRING

read -p "SigV4 Service [s3]: " AWS_SERVICE
AWS_SERVICE="${AWS_SERVICE:-s3}"

read -p "Optional payload file for PUT/POST (path) [blank for none]: " PAYLOAD_FILE
read -p "Content-Type header [default auto]: " HTTP_REQUEST_CONTENT_TYPE

read -p "Additional header params (e.g. Accept-Encoding: br;X-Custom-Thing: foo) [blank for none]: " ADDITIONAL_HEADERS


# -------- Host/URL normalization --------
normalize_host () {
  local h="$1"
  h="${h#http://}"; h="${h#https://}"  # strip scheme
  h="${h#*[@]}"                        # strip creds
  h="${h%%/*}"                         # take before slash
  printf '%s' "$h" | awk '{$1=$1;print}'
}

readonly HOST="$(normalize_host "${INPUT_HOST}")"
if [[ -z "${HOST}" ]]; then
  echo "ERROR: Host cannot be empty." >&2
  exit 1
fi

# Ensure URI starts with /
if [[ -z "${HTTP_CANONICAL_REQUEST_URI}" || "${HTTP_CANONICAL_REQUEST_URI:0:1}" != "/" ]]; then
  echo "ERROR: Canonical Request URI must start with '/'" >&2
  exit 1
fi

# -------- Helpers --------
hash_sha256 () {
  printf '%s' "$1" | openssl dgst -sha256 -hex | awk '{print $2}'
}
hash_sha256_file () {
  openssl dgst -sha256 -hex "$1" | awk '{print $2}'
}
hmac_sha256 () {
  local key_spec="$1"; local data="$2"
  printf '%s' "${data}" | openssl dgst -sha256 -mac HMAC -macopt "${key_spec}" | awk '{print $2}'
}

# -------- Dates --------
readonly CURRENT_DATE_DAY="$(date -u '+%Y%m%d')"
readonly CURRENT_DATE_TIME="$(date -u '+%H%M%S')"
readonly CURRENT_DATE_ISO8601="${CURRENT_DATE_DAY}T${CURRENT_DATE_TIME}Z"

# -------- Payload & Content-Type --------
if [[ -z "${HTTP_REQUEST_CONTENT_TYPE}" ]]; then
  case "${HTTP_REQUEST_METHOD^^}" in
    GET|HEAD|DELETE) HTTP_REQUEST_CONTENT_TYPE='application/x-www-form-urlencoded' ;;
    POST|PUT|PATCH)  HTTP_REQUEST_CONTENT_TYPE='application/octet-stream' ;;
    *)               HTTP_REQUEST_CONTENT_TYPE='application/x-www-form-urlencoded' ;;
  esac
fi

HTTP_REQUEST_PAYLOAD_HASH=''
case "${HTTP_REQUEST_METHOD^^}" in
  POST|PUT|PATCH)
    if [[ -n "${PAYLOAD_FILE}" ]]; then
      [[ -f "${PAYLOAD_FILE}" ]] || { echo "Payload file not found"; exit 1; }
      HTTP_REQUEST_PAYLOAD_HASH="$(hash_sha256_file "${PAYLOAD_FILE}")"
    else
      HTTP_REQUEST_PAYLOAD_HASH="$(hash_sha256 '')"
    fi ;;
  *) HTTP_REQUEST_PAYLOAD_HASH="$(hash_sha256 '')" ;;
esac

# -------- Canonical headers --------
HTTP_CANONICAL_REQUEST_HEADERS=$(
  printf 'content-type:%s\n' "${HTTP_REQUEST_CONTENT_TYPE}"
  printf 'host:%s\n' "${HOST}"
  printf 'x-amz-content-sha256:%s\n' "${HTTP_REQUEST_PAYLOAD_HASH}"
  printf 'x-amz-date:%s\n' "${CURRENT_DATE_ISO8601}"
)

readonly HTTP_REQUEST_SIGNED_HEADERS="content-type;host;x-amz-content-sha256;x-amz-date"

# -------- Canonical Request --------
printf -v HTTP_CANONICAL_REQUEST '%s\n%s\n%s\n%s\n\n%s\n%s' \
  "${HTTP_REQUEST_METHOD}" \
  "${HTTP_CANONICAL_REQUEST_URI}" \
  "${HTTP_CANONICAL_REQUEST_QUERY_STRING}" \
  "${HTTP_CANONICAL_REQUEST_HEADERS}" \
  "${HTTP_REQUEST_SIGNED_HEADERS}" \
  "${HTTP_REQUEST_PAYLOAD_HASH}"

# -------- String to Sign & Signature --------
create_signature () {
  local stringToSign="AWS4-HMAC-SHA256
${CURRENT_DATE_ISO8601}
${CURRENT_DATE_DAY}/${AWS_REGION}/${AWS_SERVICE}/aws4_request
$(hash_sha256 "${HTTP_CANONICAL_REQUEST}")"

  local dateKey regionKey serviceKey signingKey
  dateKey="$(hmac_sha256 "key:AWS4${AWS_SECRET_ACCESS_KEY}" "${CURRENT_DATE_DAY}")"
  regionKey="$(hmac_sha256 "hexkey:${dateKey}" "${AWS_REGION}")"
  serviceKey="$(hmac_sha256 "hexkey:${regionKey}" "${AWS_SERVICE}")"
  signingKey="$(hmac_sha256 "hexkey:${serviceKey}" "aws4_request")"

  printf '%s' "${stringToSign}" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${signingKey}" | awk '{print $2}'
}
readonly SIGNATURE="$(create_signature)"

readonly AUTH_HEADER="AWS4-HMAC-SHA256 Credential=${AWS_ACCESS_KEY_ID}/${CURRENT_DATE_DAY}/${AWS_REGION}/${AWS_SERVICE}/aws4_request, SignedHeaders=${HTTP_REQUEST_SIGNED_HEADERS}, Signature=${SIGNATURE}"

# -------- Build final URL --------
REQUEST_URL="https://${HOST}${HTTP_CANONICAL_REQUEST_URI}"
if [[ -n "${HTTP_CANONICAL_REQUEST_QUERY_STRING}" ]]; then
  REQUEST_URL="${REQUEST_URL}?${HTTP_CANONICAL_REQUEST_QUERY_STRING}"
fi

# -------- cURL invocation --------
curl -v -X "${HTTP_REQUEST_METHOD}" \
  -H "Authorization: ${AUTH_HEADER}" \
  -H "content-type: ${HTTP_REQUEST_CONTENT_TYPE}" \
  -H "x-amz-content-sha256: ${HTTP_REQUEST_PAYLOAD_HASH}" \
  -H "x-amz-date: ${CURRENT_DATE_ISO8601}" \
  $(for h in ${ADDITIONAL_HEADERS//;/ }; do echo -n "-H \"$h\" "; done) \
  ${PAYLOAD_FILE:+--data-binary @"${PAYLOAD_FILE}"} \
  "${REQUEST_URL}"
