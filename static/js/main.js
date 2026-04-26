document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('urlInput');
    const scanButton = document.getElementById('scanButton');
    const extensiveScanButton = document.getElementById('extensiveScanButton');
    const buttonText = document.getElementById('buttonText');
    const buttonSpinner = document.getElementById('buttonSpinner');
    const resultsSection = document.getElementById('results');
    const findingsList = document.getElementById('findingsList');
    const resultsFilters = document.getElementById('resultsFilters');
    const noFindings = document.getElementById('noFindings');
    const errorMessage = document.getElementById('errorMessage');
    const errorText = document.getElementById('errorText');
    const scanSummary = document.getElementById('scanSummary');
    const scanUrl = document.getElementById('scanUrl');
    const deltaSummary = document.getElementById('deltaSummary');
    const verdictBadge = document.getElementById('verdictBadge');
    const verdictReason = document.getElementById('verdictReason');
    const proofSummary = document.getElementById('proofSummary');
    const fixSummary = document.getElementById('fixSummary');
    const retestCommand = document.getElementById('retestCommand');
    const attackSection = document.getElementById('attackVectors');
    const attackSummary = document.getElementById('attackSummary');
    const attackStatus = document.getElementById('attackStatus');
    const attackList = document.getElementById('attackList');
    const attackEmpty = document.getElementById('attackEmpty');
    const scanProgress = document.getElementById('scanProgress');
    const progressText = document.getElementById('progressText');

    const extensiveScanModal = document.getElementById('extensiveScanModal');
    const closeExtensiveModal = document.getElementById('closeExtensiveModal');
    const cancelExtensiveScan = document.getElementById('cancelExtensiveScan');
    const runExtensiveScan = document.getElementById('runExtensiveScan');
    const authMode = document.getElementById('authMode');
    const bearerTokenInput = document.getElementById('bearerTokenInput');
    const cookieInput = document.getElementById('cookieInput');
    const claimedUserIdInput = document.getElementById('claimedUserIdInput');
    const modalFocusableSelector = 'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';
    let extensiveModalOpener = null;

    scanButton.addEventListener('click', () => startScan('basic'));
    extensiveScanButton.addEventListener('click', openExtensiveModal);

    if (closeExtensiveModal) {
        closeExtensiveModal.addEventListener('click', closeExtensiveScanModal);
    }
    if (cancelExtensiveScan) {
        cancelExtensiveScan.addEventListener('click', closeExtensiveScanModal);
    }
    if (runExtensiveScan) {
        runExtensiveScan.addEventListener('click', () => {
            const authConfig = {
                mode: authMode.value,
                bearer_token: bearerTokenInput.value.trim(),
                cookie: cookieInput.value.trim(),
                claimed_user_id: claimedUserIdInput.value.trim(),
            };
            if (!authConfig.bearer_token && !authConfig.cookie) {
                showError('Extensive scan requires a Bearer token or Cookie. Use throwaway test credentials.');
                return;
            }
            closeExtensiveScanModal();
            startScan('extensive', authConfig);
        });
    }

    if (extensiveScanModal) {
        extensiveScanModal.addEventListener('click', (event) => {
            if (event.target === extensiveScanModal) {
                closeExtensiveScanModal();
            }
        });
    }

    document.addEventListener('keydown', handleModalKeydown);

    urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            startScan('basic');
        }
    });

    function openExtensiveModal() {
        if (!validateUrl()) {
            return;
        }
        extensiveModalOpener = document.activeElement;
        extensiveScanModal.classList.remove('hidden');
        setTimeout(() => authMode.focus(), 0);
    }

    function closeExtensiveScanModal() {
        extensiveScanModal.classList.add('hidden');
        if (extensiveModalOpener && typeof extensiveModalOpener.focus === 'function') {
            extensiveModalOpener.focus();
        }
        extensiveModalOpener = null;
    }

    function handleModalKeydown(event) {
        if (!isExtensiveModalOpen()) {
            return;
        }
        if (event.key === 'Escape') {
            event.preventDefault();
            closeExtensiveScanModal();
            return;
        }
        if (event.key === 'Tab') {
            trapModalFocus(event);
        }
    }

    function isExtensiveModalOpen() {
        return extensiveScanModal && !extensiveScanModal.classList.contains('hidden');
    }

    function trapModalFocus(event) {
        const focusable = Array.from(extensiveScanModal.querySelectorAll(modalFocusableSelector))
            .filter(el => el.offsetParent !== null);
        if (focusable.length === 0) {
            event.preventDefault();
            return;
        }

        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) {
            event.preventDefault();
            last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
            first.focus();
        }
    }

    function validateUrl() {
        const url = urlInput.value.trim();
        if (!url) {
            showError('Please enter a URL to scan');
            return false;
        }

        if (!url.match(/^https?:\/\/.+/)) {
            showError('Please enter a valid URL starting with http:// or https://');
            return false;
        }

        return true;
    }

    function startScan(scanMode = 'basic', authConfig = {}) {
        const url = urlInput.value.trim();
        if (!validateUrl()) {
            return;
        }

        setLoading(true, scanMode);
        clearResults();
        hideError();

        const scanId = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2);
        let eventSource = null;

        if (scanProgress && progressText) {
            scanProgress.classList.remove('hidden');
            progressText.textContent = 'Initializing...';
            eventSource = new EventSource('/scan/events/' + scanId);
            eventSource.onmessage = function(event) {
                try {
                    const msg = JSON.parse(event.data);
                    if (msg.type === 'progress') {
                        progressText.textContent = msg.message;
                    } else if (msg.type === 'result' || msg.type === 'error') {
                        eventSource.close();
                    }
                } catch (e) {
                    // Ignore malformed progress messages.
                }
            };
            eventSource.onerror = function() {
                eventSource.close();
            };
        }

        fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                url: url,
                scan_mode: scanMode,
                auth_config: authConfig,
                scan_id: scanId,
            })
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => {
                    throw new Error(err.error || 'An error occurred');
                });
            }
            return response.json();
        })
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }
            displayResults(data);
            resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        })
        .catch(error => {
            showError(error.message || 'An error occurred while scanning the URL');
            console.error('Error:', error);
        })
        .finally(() => {
            setLoading(false, scanMode);
            if (scanProgress) scanProgress.classList.add('hidden');
            if (eventSource) eventSource.close();
        });
    }

    function setLoading(isLoading, scanMode = 'basic') {
        if (isLoading) {
            scanButton.disabled = true;
            extensiveScanButton.disabled = true;
            buttonText.textContent = scanMode === 'extensive' ? 'EXTENSIVE...' : 'BASIC SCAN';
            buttonSpinner.classList.remove('hidden');
            scanButton.classList.remove('hover:bg-emerald-500');
            extensiveScanButton.classList.remove('hover:bg-violet-500');
        } else {
            scanButton.disabled = false;
            extensiveScanButton.disabled = false;
            buttonText.textContent = 'BASIC SCAN';
            buttonSpinner.classList.add('hidden');
            scanButton.classList.add('hover:bg-emerald-500');
            extensiveScanButton.classList.add('hover:bg-violet-500');
        }
    }

    function clearResults() {
        findingsList.innerHTML = '';
        scanSummary.innerHTML = '';
        resultsSection.classList.add('hidden');
        noFindings.classList.add('hidden');

        if (resultsFilters) {
            resultsFilters.innerHTML = '';
            resultsFilters.classList.add('hidden');
        }
        if (deltaSummary) {
            deltaSummary.classList.add('hidden');
        }

        attackSummary.innerHTML = '';
        attackStatus.textContent = '';
        attackList.innerHTML = '';
        attackSection.classList.add('hidden');
        attackEmpty.classList.add('hidden');
    }

    function displayResults(data) {
        resultsSection.classList.remove('hidden');
        resultsSection.classList.add('fade-in');

        if (data.url) {
            scanUrl.textContent = data.url;
        }

        displayDeltaSummary(data);

        if (data.scan_summary) {
            const { total_findings, critical_severity, high_severity, medium_severity, low_severity } = data.scan_summary;
            const scanModeBadge = data.scan_mode ? `<div class="bg-violet-900/20 px-3 py-1 rounded border border-violet-800"><span class="text-violet-300">${escapeHtml(data.scan_mode)}</span><span class="text-violet-400 ml-1">mode</span></div>` : '';

            scanSummary.innerHTML = `
                <div class="flex flex-wrap gap-2 font-mono text-xs">
                    ${scanModeBadge}
                    <div class="bg-slate-900/80 px-3 py-1 rounded border border-slate-600">
                        <span class="text-emerald-400">${total_findings}</span>
                        <span class="text-slate-500 ml-1">total</span>
                    </div>
                    ${critical_severity > 0 ? `<div class="bg-red-900/30 px-3 py-1 rounded border border-red-700"><span class="text-red-400">${critical_severity}</span><span class="text-red-500 ml-1">crit</span></div>` : ''}
                    ${high_severity > 0 ? `<div class="bg-red-900/20 px-3 py-1 rounded border border-red-800"><span class="text-red-400">${high_severity}</span><span class="text-red-500 ml-1">high</span></div>` : ''}
                    ${medium_severity > 0 ? `<div class="bg-yellow-900/20 px-3 py-1 rounded border border-yellow-800"><span class="text-yellow-400">${medium_severity}</span><span class="text-yellow-500 ml-1">med</span></div>` : ''}
                    ${low_severity > 0 ? `<div class="bg-blue-900/20 px-3 py-1 rounded border border-blue-800"><span class="text-blue-400">${low_severity}</span><span class="text-blue-500 ml-1">low</span></div>` : ''}
                </div>
            `;
        }

        displayFilters(data.findings || []);

        if (data.findings && data.findings.length > 0) {
            data.findings.forEach(finding => {
                findingsList.appendChild(renderFinding(finding));
            });
        } else {
            noFindings.classList.remove('hidden');
        }

        displayAttackVectors(data.attack_vectors);
    }

    function displayDeltaSummary(data) {
        if (!deltaSummary) {
            return;
        }

        const reportFindings = data.report && Array.isArray(data.report.findings) ? data.report.findings : [];
        const firstFinding = reportFindings[0];
        const verdict = data.verdict || (data.report && data.report.verdict) || {
            label: reportFindings.length ? 'REVIEW' : 'SAFE TO SHIP',
            reason: reportFindings.length ? 'Findings need review.' : 'No medium, high, or critical findings were detected in this scan.',
            status: reportFindings.length ? 'REVIEW' : 'SAFE_TO_SHIP',
        };

        verdictBadge.textContent = verdict.label || 'REVIEW';
        verdictBadge.className = 'verdict-badge';
        if (verdict.status === 'BLOCK_SHIP') {
            verdictBadge.classList.add('verdict-block');
        } else if (verdict.status === 'SAFE_TO_SHIP') {
            verdictBadge.classList.add('verdict-safe');
        } else {
            verdictBadge.classList.add('verdict-review');
        }

        verdictReason.textContent = verdict.reason || '';
        retestCommand.textContent = data.retest_command || (data.report && data.report.retest_command) || '';

        if (firstFinding) {
            const evidence = firstFinding.evidence || {};
            proofSummary.textContent = `${formatType(firstFinding.type)} in ${evidence.source || firstFinding.source || 'unknown source'}: ${evidence.redacted_value || firstFinding.redacted_value || 'evidence redacted'}`;
            fixSummary.textContent = firstFinding.remediation || 'Review and remove the exposed sensitive data.';
        } else {
            proofSummary.textContent = 'No proof needed: this scan did not find reportable exposures.';
            fixSummary.textContent = 'No fix required from this scan. Re-test after meaningful deploys or config changes.';
        }

        deltaSummary.classList.remove('hidden');
    }

    function displayFilters(findings) {
        if (!resultsFilters || findings.length === 0) {
            return;
        }

        resultsFilters.classList.remove('hidden');
        const filterDiv = document.createElement('div');
        filterDiv.className = 'filter-row';
        const filterLabel = document.createElement('span');
        filterLabel.className = 'text-xs font-mono text-slate-500';
        filterLabel.textContent = 'FILTER:';
        filterDiv.appendChild(filterLabel);

        const filterColors = {
            critical: 'border-red-700 text-red-400 bg-red-900/30',
            high: 'border-red-800 text-red-400 bg-red-900/20',
            medium: 'border-yellow-800 text-yellow-400 bg-yellow-900/20',
            low: 'border-blue-800 text-blue-400 bg-blue-900/20',
        };

        ['critical', 'high', 'medium', 'low'].forEach(sev => {
            const btn = document.createElement('button');
            btn.className = `filter-button font-mono ${filterColors[sev]}`;
            btn.dataset.severity = sev;
            btn.dataset.active = 'true';
            btn.textContent = sev.toUpperCase();
            btn.addEventListener('click', () => {
                const nowActive = btn.dataset.active !== 'true';
                btn.dataset.active = nowActive ? 'true' : 'false';
                document.querySelectorAll(`.finding-card.severity-${sev}`).forEach(el => {
                    el.classList.toggle('filtered-out', !nowActive);
                });
            });
            filterDiv.appendChild(btn);
        });

        resultsFilters.appendChild(filterDiv);
    }

    function renderFinding(finding) {
        const findingElement = document.createElement('div');
        findingElement.className = `p-6 finding-card severity-${finding.severity || 'low'}`;

        let severityIcon = '○';
        let severityColor = 'text-blue-400';
        let badgeClass = 'bg-blue-900/30 border-blue-700 text-blue-400';

        if (finding.severity === 'critical') {
            severityIcon = '!';
            severityColor = 'text-red-400';
            badgeClass = 'bg-red-900/30 border-red-700 text-red-400';
        } else if (finding.severity === 'high') {
            severityIcon = '●';
            severityColor = 'text-red-400';
            badgeClass = 'bg-red-900/20 border-red-800 text-red-400';
        } else if (finding.severity === 'medium') {
            severityIcon = '●';
            severityColor = 'text-yellow-400';
            badgeClass = 'bg-yellow-900/20 border-yellow-800 text-yellow-400';
        }

        findingElement.innerHTML = `
            <div class="space-y-3">
                <div class="flex items-start justify-between gap-4 flex-wrap">
                    <div class="flex items-start gap-3">
                        <span class="${severityColor} text-xl font-mono">${severityIcon}</span>
                        <div>
                            <h3 class="text-sm font-bold text-slate-200 font-mono">${formatType(finding.type)}</h3>
                            <span class="text-xs font-mono px-2 py-0.5 rounded border ${badgeClass} inline-block mt-1">
                                ${(finding.severity || 'low').toUpperCase()}
                            </span>
                        </div>
                    </div>
                </div>

                <div class="space-y-2 text-sm">
                    <div>
                        <p class="text-slate-500 text-xs font-mono mb-1">VALUE:</p>
                        <div class="bg-slate-900 border border-slate-700 rounded p-2 overflow-x-auto">
                            <code class="text-xs font-mono text-emerald-400 break-all">${escapeHtml(finding.value || finding.match || 'N/A')}</code>
                        </div>
                    </div>

                    ${finding.source ? `<div class="text-xs font-mono break-all"><span class="text-slate-500">SOURCE:</span><span class="text-slate-400 ml-2">${escapeHtml(finding.source)}</span></div>` : ''}
                    ${finding.line ? `<div class="text-xs font-mono"><span class="text-slate-500">LINE:</span><span class="text-slate-400 ml-2">${finding.line}</span></div>` : ''}
                    ${finding.context_lines ? `<div><p class="text-slate-500 text-xs font-mono mb-1">CONTEXT:</p><div class="bg-slate-900 rounded p-3 overflow-x-auto border border-slate-700"><pre class="text-xs font-mono text-slate-400 whitespace-pre"><code>${escapeHtml(finding.context_lines)}</code></pre></div></div>` : ''}
                    ${finding.recommendation ? `<div class="bg-slate-900/50 border border-slate-700 rounded p-3"><p class="text-slate-500 text-xs font-mono mb-1">FIX:</p><p class="text-slate-400 text-xs leading-relaxed">${escapeHtml(finding.recommendation)}</p></div>` : ''}
                </div>
            </div>
        `;
        return findingElement;
    }

    function displayAttackVectors(attackVectors) {
        if (!attackVectors) {
            return;
        }

        attackSection.classList.remove('hidden');
        attackSection.classList.add('fade-in');
        attackSummary.innerHTML = buildSummaryBadges(attackVectors.summary || {});

        const status = attackVectors.status || 'unknown';
        const elapsed = attackVectors.elapsed_seconds ? `${attackVectors.elapsed_seconds}s` : 'n/a';
        const enumTool = attackVectors.enumerator && attackVectors.enumerator.tool ? attackVectors.enumerator.tool : 'none';
        const enumError = attackVectors.enumerator && attackVectors.enumerator.error ? attackVectors.enumerator.error : null;

        let statusText = `status: ${status} | enumerator: ${enumTool} | elapsed: ${elapsed}`;
        if (enumError) {
            statusText += ` | enum error: ${enumError}`;
        }
        attackStatus.textContent = statusText;

        attackList.innerHTML = '';
        attackEmpty.classList.add('hidden');

        if (!attackVectors.subdomains || attackVectors.subdomains.length === 0) {
            attackEmpty.classList.remove('hidden');
            return;
        }

        attackVectors.subdomains.forEach((hostResult, index) => {
            const container = document.createElement('details');
            container.className = 'group p-5';
            container.style.animationDelay = `${index * 0.05}s`;
            container.classList.add('fade-in');

            const hostSummary = buildSummaryBadges(hostResult.summary || {});
            const findings = hostResult.findings || [];

            container.innerHTML = `
                <summary class="flex flex-col md:flex-row md:items-start md:justify-between gap-3 cursor-pointer list-none">
                    <div class="flex items-start gap-3">
                        <span class="text-emerald-400 font-mono text-sm">+</span>
                        <div>
                            <div class="text-sm font-bold text-slate-200 font-mono">${escapeHtml(hostResult.host || 'unknown')}</div>
                            <div class="text-xs text-slate-500 font-mono break-all">${escapeHtml(hostResult.url || '')}</div>
                        </div>
                    </div>
                    <div class="attack-summary">${hostSummary}</div>
                </summary>
                <div class="mt-4 space-y-3">
                    ${findings.length === 0 ? `
                        <div class="text-xs text-slate-500 font-mono">No attack vectors detected for this host.</div>
                    ` : ''}
                </div>
            `;

            const findingsContainer = container.querySelector('.space-y-3');
            findings.forEach((finding) => {
                const findingElement = document.createElement('div');
                findingElement.className = `p-4 rounded border border-slate-700 bg-slate-900/40 severity-${finding.severity || 'low'}`;
                findingElement.innerHTML = `
                    <div class="flex items-start justify-between gap-3">
                        <div>
                            <div class="text-xs text-slate-500 font-mono">TYPE</div>
                            <div class="text-sm text-slate-200 font-mono">${escapeHtml(formatType(finding.type || 'finding'))}</div>
                        </div>
                        <div class="text-xs font-mono text-slate-500">${escapeHtml((finding.severity || 'low').toUpperCase())}</div>
                    </div>
                    <div class="mt-2 text-xs text-slate-400 font-mono break-words">${escapeHtml(finding.details || finding.value || '')}</div>
                    ${finding.url ? `
                        <div class="mt-2 text-xs text-slate-500 font-mono break-all">URL: ${escapeHtml(finding.url)}</div>
                    ` : ''}
                    ${finding.recommendation ? `
                        <div class="mt-3 bg-slate-900/70 border border-slate-700 rounded p-2">
                            <div class="text-xs text-slate-500 font-mono mb-1">FIX</div>
                            <div class="text-xs text-slate-400 font-mono">${escapeHtml(finding.recommendation)}</div>
                        </div>
                    ` : ''}
                `;
                findingsContainer.appendChild(findingElement);
            });

            attackList.appendChild(container);
        });
    }

    function buildSummaryBadges(summary) {
        const total = summary.total_findings || 0;
        const critical = summary.critical_severity || 0;
        const high = summary.high_severity || 0;
        const medium = summary.medium_severity || 0;
        const low = summary.low_severity || 0;

        return `
            <div class="flex flex-wrap gap-2 font-mono text-xs">
                <div class="bg-slate-900/80 px-3 py-1 rounded border border-slate-600">
                    <span class="text-emerald-400">${total}</span>
                    <span class="text-slate-500 ml-1">total</span>
                </div>
                ${critical > 0 ? `<div class="bg-red-900/30 px-3 py-1 rounded border border-red-700"><span class="text-red-400">${critical}</span><span class="text-red-500 ml-1">crit</span></div>` : ''}
                ${high > 0 ? `<div class="bg-red-900/20 px-3 py-1 rounded border border-red-800"><span class="text-red-400">${high}</span><span class="text-red-500 ml-1">high</span></div>` : ''}
                ${medium > 0 ? `<div class="bg-yellow-900/20 px-3 py-1 rounded border border-yellow-800"><span class="text-yellow-400">${medium}</span><span class="text-yellow-500 ml-1">med</span></div>` : ''}
                ${low > 0 ? `<div class="bg-blue-900/20 px-3 py-1 rounded border border-blue-800"><span class="text-blue-400">${low}</span><span class="text-blue-500 ml-1">low</span></div>` : ''}
            </div>
        `;
    }

    function showError(message) {
        errorText.textContent = message;
        errorMessage.classList.remove('hidden');
        errorMessage.classList.add('fade-in');
        errorMessage.scrollIntoView({ behavior: 'smooth', block: 'center' });

        setTimeout(() => {
            hideError();
        }, 10000);
    }

    function hideError() {
        errorMessage.classList.add('hidden');
    }

    function formatType(type) {
        if (!type) {
            return 'UNKNOWN';
        }
        return String(type).split('_').join(' ').toUpperCase();
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text || '';
        return div.innerHTML;
    }

    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });
});
