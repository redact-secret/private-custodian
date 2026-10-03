"""Authorized synthetic health/lifecycle experiment; never a custody dispatcher.

Consumes a private configuration outside Git. Creates at most two health-only
VMs, with no execution role, disabled logs and a specified VPC egress connector.
Persists creation intents before dispatch; replay uses the identical client token.
Only fixed codes, booleans and durations are printable. Endpoint tokens stay in
memory. Cleanup must also be reconciled from the private inventory after a crash.
"""
import argparse
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class Refused(Exception):
    pass


def private_read(path):
    path = Path(path)
    repository = Path(__file__).resolve().parents[3]
    if path.is_symlink() or path.resolve().is_relative_to(repository):
        raise Refused("PRIVATE_PATH_REQUIRED")
    meta = path.stat()
    parent = path.parent.stat()
    if (meta.st_uid != os.getuid() or meta.st_mode & 0o077
            or parent.st_uid != os.getuid() or parent.st_mode & 0o077):
        raise Refused("PRIVATE_PERMISSIONS_REQUIRED")
    if meta.st_size > 65536:
        raise Refused("CONFIG_TOO_LARGE")
    return json.loads(path.read_text())


def private_write(path, value):
    path = Path(path)
    if path.is_symlink():
        raise Refused("PRIVATE_PATH_REQUIRED")
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def aws(config, operation, params):
    env = dict(os.environ, AWS_MAX_ATTEMPTS="1")
    result = subprocess.run(
        ["aws", "--profile", config["profile"], "--region", config["region"],
         "lambda-microvms", operation, "--cli-input-json", json.dumps(params),
         "--output", "json", "--no-cli-pager"],
        capture_output=True, text=True, timeout=120, env=env,
    )
    if result.returncode:
        match = re.search(r"\(([A-Za-z]+Exception)\)", result.stderr)
        allowed = {"ResourceNotFoundException", "ValidationException",
                   "ServiceQuotaExceededException", "ResourceConflictException"}
        raise Refused(match.group(1) if match and match.group(1) in allowed
                      else "AWS_REQUEST_REFUSED")
    return json.loads(result.stdout or "{}")


def http(endpoint, path, token=None, port=8080, method="GET"):
    url = urllib.parse.urlsplit(endpoint if endpoint.startswith("https://")
                                else "https://" + endpoint)
    if (url.scheme != "https" or url.username or url.password or url.query
            or url.fragment or url.path not in ("", "/") or not url.hostname
            or not re.fullmatch(r"[a-z0-9-]+\.lambda-microvm\.[a-z0-9-]+\.on\.aws",
                                url.hostname)):
        raise Refused("ENDPOINT_REFUSED")
    headers = {"X-aws-proxy-port": str(port)}
    if token:
        headers["X-aws-proxy-auth"] = token
    request = urllib.request.Request(
        urllib.parse.urlunsplit((url.scheme, url.netloc, path, "", "")),
        headers=headers, method=method, data=b"" if method == "POST" else None,
    )
    ca = next((p for p in ("/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt")
               if Path(p).is_file()), None)
    context = ssl.create_default_context(cafile=ca)
    # Never follow redirects with an authentication token.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(NoRedirect(),
                                         urllib.request.HTTPSHandler(context=context))
    try:
        response = opener.open(request, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read(4097)
        if len(body) > 4096:
            raise Refused("HTTP_OUTPUT_LIMIT")
        return response.code, body


def experiment(config, inventory, call=aws, request=http, clock=time.monotonic,
               sleep=time.sleep):
    if config.get("syntheticOnly") is not True or config.get("maxUsd") != 50:
        raise Refused("AUTHORIZATION_REQUIRED")
    if not config.get("egressConnectorArn") or not config.get("imageVersion"):
        raise Refused("EXACT_CONFIGURATION_REQUIRED")
    if Path(inventory).exists():
        raise Refused("RECONCILE_EXISTING_INVENTORY")
    # Atomic one-writer ownership; concurrent invocations cannot overwrite an
    # inventory and hide one another's VM creation intents.
    try:
        fd = os.open(inventory, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
    except FileExistsError:
        raise Refused("RECONCILE_EXISTING_INVENTORY") from None
    state = {"schema": 1, "config": config, "intents": [], "vms": []}
    private_write(inventory, state)
    report = {"schema": "private-custodian.microvm-health-evidence/1",
              "synthetic": True, "isolationVerified": False, "checks": {}}
    checks = report["checks"]
    started = clock()
    try:
        image = call(config, "get-microvm-image-version", {
            "imageIdentifier": config["imageArn"], "imageVersion": config["imageVersion"]})
        if (image.get("state") != "SUCCESSFUL" or image.get("status") != "ACTIVE"
                or image.get("imageArn") != config["imageArn"]
                or image.get("imageVersion") != config["imageVersion"]
                or image.get("logging") != {"disabled": {}}
                or image.get("cpuConfigurations") != [{"architecture": "ARM_64"}]
                or image.get("resources") != [{"minimumMemoryInMiB": 512}]
                or image.get("additionalOsCapabilities")
                or image.get("environmentVariables")
                or image.get("hooks", {}).get("microvmImageHooks", {}).get("ready") != "ENABLED"
                or image.get("hooks", {}).get("microvmImageHooks", {}).get("validate") != "ENABLED"):
            raise Refused("IMAGE_CONFIGURATION_REFUSED")
        checks["explicitImageConfiguration"] = True
        for lifetime in (180, 60):
            params = {
                "imageIdentifier": config["imageArn"],
                "imageVersion": config["imageVersion"],
                "ingressNetworkConnectors": [
                    f"arn:aws:lambda:{config['region']}:aws:network-connector:"
                    "aws-network-connector:HTTP_INGRESS"],
                "egressNetworkConnectors": [config["egressConnectorArn"]],
                "logging": {"disabled": {}},
                "idlePolicy": {"autoResumeEnabled": False,
                               "maxIdleDurationSeconds": 28800,
                               "suspendedDurationSeconds": 1},
                "maximumDurationInSeconds": lifetime,
                "clientToken": uuid.uuid4().hex,
            }
            state["intents"].append(params)
            state["unresolvedCreation"] = True
            private_write(inventory, state)
            vm = call(config, "run-microvm", params)
            state["vms"].append(vm)
            private_write(inventory, state)
            # Lost-response control: replay the exact creation intent.
            replay = call(config, "run-microvm", params)
            if vm["microvmId"] != replay["microvmId"]:
                state["vms"].append(replay)
                state["unresolvedCreation"] = False
                private_write(inventory, state)
                raise Refused("CREATION_REPLAY_CONFLICT")
            state["unresolvedCreation"] = False
            private_write(inventory, state)
        first, second = state["vms"]
        checks["creationReplaySameVm"] = True
        checks["freshVmDistinct"] = first["microvmId"] != second["microvmId"]
        token = call(config, "create-microvm-auth-token", {
            "microvmIdentifier": first["microvmId"], "expirationInMinutes": 1,
            "allowedPorts": [{"port": 8080}],
        })["authToken"]["X-aws-proxy-auth"]
        token_at = clock()
        code, body = request(first["endpoint"], "/health", token)
        checks["health"] = code == 200 and body == b'{"synthetic":true,"verified":false}'
        for name, target, supplied, port in (
            ("missingTokenDenied", first, None, 8080),
            ("invalidTokenDenied", first, "SYNTHETIC-INVALID", 8080),
            ("wrongPortDenied", first, token, 8081),
            ("wrongVmDenied", second, token, 8080),
        ):
            checks[name] = request(target["endpoint"], "/health", supplied, port)[0] == 403
        checks["jobRefused"] = request(first["endpoint"], "/job", token,
                                       method="POST") == (403, b"")
        try:
            call(config, "create-microvm-shell-auth-token", {
                "microvmIdentifier": first["microvmId"], "expirationInMinutes": 1,
            })
            checks["shellTokenDenied"] = False
        except Refused as error:
            checks["shellTokenDenied"] = str(error) == "ValidationException"
        while clock() - token_at < 65:
            sleep(min(5, 65 - (clock() - token_at)))
        status = request(first["endpoint"], "/health", token)[0]
        report["expiryProbeHttpStatus"] = status
        checks["expiredTokenDenied"] = status == 403
        for _ in range(12):
            vm = call(config, "get-microvm", {"microvmIdentifier": second["microvmId"]})
            if vm.get("state") == "TERMINATED":
                break
            sleep(5)
        checks["maximumLifetimeTerminates"] = vm.get("state") == "TERMINATED"
    except Exception as error:
        fixed = {"CREATION_REPLAY_CONFLICT", "ENDPOINT_REFUSED", "HTTP_OUTPUT_LIMIT",
                 "IMAGE_CONFIGURATION_REFUSED",
                 "ResourceNotFoundException", "ValidationException",
                 "ServiceQuotaExceededException", "ResourceConflictException",
                 "AWS_REQUEST_REFUSED"}
        report["refusal"] = str(error) if str(error) in fixed else "EXPERIMENT_FAILED"
    finally:
        # Cleanup never launches a VM. Unresolved intents need the independent
        # exact-image orphan inventory; maximumDuration bounds lost responses.
        known = {vm["microvmId"] for vm in state["vms"]}
        if state.get("unresolvedCreation") or len(state["vms"]) < len(state["intents"]):
            report["creationReconciliationIncomplete"] = True
        terminal = []
        for vm in state["vms"]:
            try:
                call(config, "terminate-microvm", {"microvmIdentifier": vm["microvmId"]})
                for _ in range(12):
                    current = call(config, "get-microvm", {
                        "microvmIdentifier": vm["microvmId"]})
                    if current.get("state") == "TERMINATED":
                        break
                    sleep(5)
                terminal.append(current.get("state") == "TERMINATED")
            except Exception:
                terminal.append(False)
        report["vmCount"] = len(known)
        report["vmCleanupVerified"] = (bool(terminal) and all(terminal)
                                          and not report.get("creationReconciliationIncomplete"))
        report["elapsedSeconds"] = round(clock() - started, 3)
        state["report"] = report
        private_write(inventory, state)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-config", required=True)
    args = parser.parse_args()
    try:
        config = private_read(args.private_config)
        report = experiment(config, str(Path(args.private_config).with_suffix(".vms.json")))
    except Exception:
        report = {"refusal": "PRIVATE_CONFIGURATION_REFUSED"}
    print(json.dumps(report, sort_keys=True))
