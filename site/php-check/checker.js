"use strict";

function assessPHPVersion(raw) {
    const version = raw.trim().replace(/^PHP\//i, "");
    const result = {status: "unknown", version: "", reason: "Enter a complete stable version. Vendor builds and prereleases need vendor patch verification."};
    if (!/^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$/.test(version)) return result;
    const [major, minor, patch] = version.split(".").map(Number);
    const fixed = {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}[`${major}.${minor}`];
    result.version = version;
    if (fixed !== undefined) result.status = patch >= fixed ? "patched_version_reported" : "potentially_affected";
    else if (major < 8 || (major === 8 && minor < 2)) result.status = "potentially_affected";
    if (result.status === "potentially_affected") result.reason = "This version predates the upstream fixes. Vendor backports may apply.";
    else if (result.status === "patched_version_reported") result.reason = "This is an upstream patched version. Verify it is deployed on every serving worker.";
    else result.reason = "This release branch is outside this advisory snapshot. Check with its vendor.";
    return result;
}

if (typeof module !== "undefined") module.exports = {assessPHPVersion};

if (typeof document !== "undefined") {
    const titles = {unknown: "Patch status unknown", potentially_affected: "Potentially affected", patched_version_reported: "Patched version reported"};
    const result = document.getElementById("result");
    const error = document.getElementById("error");
    let activeController = null;
    function show(assessment) {
        if (!titles[assessment.status]) throw new Error("The checker returned an invalid result.");
        result.hidden = false;
        document.getElementById("result-title").textContent = titles[assessment.status];
        document.getElementById("result-version").textContent = assessment.version ? `PHP version: ${assessment.version}` : "No reliable version established.";
        document.getElementById("result-reason").textContent = assessment.reason;
        result.scrollIntoView({behavior: "smooth", block: "nearest"});
    }
    document.getElementById("version-form").addEventListener("submit", event => {
        event.preventDefault();
        if (activeController) activeController.abort();
        activeController = null;
        const button = document.getElementById("check-url");
        button.disabled = false;
        button.textContent = "Check PHP version";
        error.textContent = "";
        show(assessPHPVersion(document.getElementById("version").value));
    });
    document.getElementById("url-form").addEventListener("submit", async event => {
        event.preventDefault();
        const button = document.getElementById("check-url");
        if (activeController) activeController.abort();
        button.disabled = true;
        button.textContent = "Checking response headers…";
        result.hidden = true;
        error.textContent = "";
        const controller = new AbortController();
        activeController = controller;
        const deadline = setTimeout(() => controller.abort(), 15000);
        const endpoint = location.hostname.endsWith(".onrender.com") ? "/api/check" : "https://keyleak-php-check.onrender.com/api/check";
        try {
            const response = await fetch(endpoint, {method: "POST", credentials: "omit", signal: controller.signal,
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({url: document.getElementById("url").value, authorized: document.getElementById("authorized").checked})});
            const assessment = await response.json().catch(() => ({error: "The checker is temporarily unavailable. Try the version comparison below."}));
            if (activeController !== controller) return;
            if (!response.ok) throw new Error(assessment.error || "The checker could not complete this request.");
            if (assessment.error) throw new Error(assessment.error);
            show(assessment);
        } catch (failure) {
            if (activeController === controller) {
                error.textContent = failure.name === "AbortError" ? "The check timed out. Patch status is unknown; try the version comparison below." : failure.message;
            }
        } finally {
            clearTimeout(deadline);
            if (activeController === controller) {
                activeController = null;
                button.disabled = false;
                button.textContent = "Check PHP version";
            }
        }
    });
}
