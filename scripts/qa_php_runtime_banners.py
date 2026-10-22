"""Opt-in QA: ordinary HTTP responses from isolated, digest-pinned PHP runtimes.

Run from the checkout with `python -m scripts.qa_php_runtime_banners`.
Requires Docker. No runtime is published or given network access.
"""

import io
import json
import secrets
import subprocess
import sys
import tarfile
import time

from keyleak.php_scanner import assess_php_headers


def main():
    run_id = secrets.token_hex(4)
    containers, images, results = [], [], []
    runtimes = [
        ("8.3.35", "b62d1f1ff98037e7ec8ee5e5ed382bfe2d88d054b05e0d09bcc851e3342072c2"),
        ("8.3.36", "74caa458ad8d6c5e401eb9f8841a62faeab9b7be42b54cd37986d7685f857618"),
    ]
    try:
        for version, digest in runtimes:
            image = f"keyleak-php-qa:{run_id}-{version}"
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w") as tar:
                for name, text in [
                    ("Dockerfile", f"FROM php@sha256:{digest}\nCOPY index.php /qa/index.php\n"),
                    ("index.php", "<?php header('Content-Type: text/plain'); echo PHP_VERSION;"),
                ]:
                    content = text.encode()
                    item = tarfile.TarInfo(name)
                    item.size, item.mode = len(content), 0o644
                    tar.addfile(item, io.BytesIO(content))
            subprocess.run(["docker", "build", "--network=none", "--tag", image, "-"],
                           input=archive.getvalue(), stdout=sys.stderr, check=True, timeout=180)
            images.append(image)
            for exposed in ([1, 0] if version == "8.3.35" else [1]):
                command = ["docker", "run", "--detach", "--rm", "--network=none",
                           "--user=65534:65534", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                           "--read-only", "--tmpfs=/tmp:rw,noexec,nosuid,size=8m", "--memory=64m",
                           "--cpus=0.25", "--pids-limit=32", image, "php", "-d", f"expose_php={exposed}",
                           "-S", "127.0.0.1:8080", "-t", "/qa"]
                container = subprocess.check_output(command, text=True, timeout=30).strip()
                containers.append(container)
                probe = ('$body=file_get_contents("http://127.0.0.1:8080/");'
                         'echo json_encode(["body"=>$body,"headers"=>$http_response_header]);')
                response = None
                for attempt in range(20):
                    fetched = subprocess.run(["docker", "exec", container, "php", "-r", probe],
                                             capture_output=True, text=True, timeout=5)
                    if fetched.returncode == 0:
                        response = json.loads(fetched.stdout)
                        if response.get("body") == version:
                            break
                    time.sleep(0.25)
                assert response and response["body"] == version, response
                headers = dict(line.split(":", 1) for line in response["headers"] if ":" in line)
                headers = {key: value.strip() for key, value in headers.items()}
                expected = "unknown" if not exposed else (
                    "potentially_affected" if version == "8.3.35" else "patched_version_reported")
                assessment = assess_php_headers(headers)
                assert assessment["status"] == expected, assessment
                results.append({"php_version": version, "image_digest": "sha256:" + digest,
                                "expose_php": bool(exposed), "expected": expected,
                                "assessment": assessment, "network": "none", "published_ports": []})
        print(json.dumps(results, indent=2))
    finally:
        failures = []
        for container in containers:
            result = subprocess.run(["docker", "rm", "--force", container], capture_output=True, text=True, timeout=20)
            if result.returncode and "No such container" not in result.stderr:
                failures.append(result.stderr)
        for image in images:
            result = subprocess.run(["docker", "image", "rm", image], capture_output=True, text=True, timeout=20)
            if result.returncode:
                failures.append(result.stderr)
        if failures:
            raise RuntimeError("QA cleanup failed: " + "; ".join(failures))


if __name__ == "__main__":
    main()
