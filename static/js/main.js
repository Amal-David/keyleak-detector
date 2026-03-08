document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('urlInput');
    const scanButton = document.getElementById('scanButton');
    const extensiveScanButton = document.getElementById('extensiveScanButton');
    const buttonText = document.getElementById('buttonText');
    const buttonSpinner = document.getElementById('buttonSpinner');
    const resultsSection = document.getElementById('results');
    const findingsList = document.getElementById('findingsList');
    const noFindings = document.getElementById('noFindings');
    const errorMessage = document.getElementById('errorMessage');
    const errorText = document.getElementById('errorText');
    const scanSummary = document.getElementById('scanSummary');
    const scanUrl = document.getElementById('scanUrl');

    const extensiveScanModal = document.getElementById('extensiveScanModal');
    const closeExtensiveModal = document.getElementById('closeExtensiveModal');
    const cancelExtensiveScan = document.getElementById('cancelExtensiveScan');
    const runExtensiveScan = document.getElementById('runExtensiveScan');
    const authMode = document.getElementById('authMode');
    const bearerTokenInput = document.getElementById('bearerTokenInput');
    const cookieInput = document.getElementById('cookieInput');
    const claimedUserIdInput = document.getElementById('claimedUserIdInput');

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

    urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            startScan('basic');
        }
    });

    function openExtensiveModal() {
        if (!validateUrl()) {
            return;
        }
        extensiveScanModal.classList.remove('hidden');
    }

    function closeExtensiveScanModal() {
        extensiveScanModal.classList.add('hidden');
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

        if (scanMode === 'extensive') {
            const usingAuthArtifacts = authConfig.bearer_token || authConfig.cookie;
            if (!usingAuthArtifacts) {
                showError('Extensive scan selected without auth context. You can still run it, but authenticated IDOR checks are stronger with throwaway token/cookie.');
            }
        }

        setLoading(true, scanMode);
        clearResults();
        hideError();

        fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                url: url,
                scan_mode: scanMode,
                auth_config: authConfig,
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
    }

    function displayResults(data) {
        resultsSection.classList.remove('hidden');
        resultsSection.classList.add('fade-in');

        if (data.url) {
            scanUrl.textContent = data.url;
        }

        if (data.scan_summary) {
            const { total_findings, critical_severity, high_severity, medium_severity, low_severity } = data.scan_summary;
            const scanModeBadge = data.scan_mode ? `<div class="bg-violet-900/20 px-3 py-1 rounded border border-violet-800"><span class="text-violet-300">${escapeHtml(data.scan_mode)}</span><span class="text-violet-400 ml-1">mode</span></div>` : '';

            if (total_findings === 0) {
                noFindings.classList.remove('hidden');
                scanSummary.innerHTML = scanModeBadge;
                return;
            }

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

        if (data.findings && data.findings.length > 0) {
            data.findings.forEach(finding => {
                const findingElement = document.createElement('div');
                findingElement.className = `p-6 finding-card severity-${finding.severity || 'low'}`;

                let severityIcon = '○';
                let severityColor = 'text-blue-400';
                let badgeClass = 'bg-blue-900/30 border-blue-700 text-blue-400';

                if (finding.severity === 'critical') {
                    severityIcon = '⚠';
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

                const formatType = (type) => {
                    return type.split('_').join(' ').toUpperCase();
                };

                findingElement.innerHTML = `
                    <div class="space-y-3">
                        <div class="flex items-start justify-between gap-4">
                            <div class="flex items-start gap-3">
                                <span class="${severityColor} text-xl font-mono">${severityIcon}</span>
                                <div>
                                    <h3 class="text-sm font-bold text-slate-200 font-mono">${formatType(finding.type)}</h3>
                                    <span class="text-xs font-mono px-2 py-0.5 rounded border ${badgeClass} inline-block mt-1">
                                        ${finding.severity.toUpperCase()}
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

                            ${finding.source ? `<div class="text-xs font-mono"><span class="text-slate-500">SOURCE:</span><span class="text-slate-400 ml-2">${escapeHtml(finding.source)}</span></div>` : ''}
                            ${finding.line ? `<div class="text-xs font-mono"><span class="text-slate-500">LINE:</span><span class="text-slate-400 ml-2">${finding.line}</span></div>` : ''}

                            ${finding.context_lines ? `<div><p class="text-slate-500 text-xs font-mono mb-1">CONTEXT:</p><div class="bg-slate-900 rounded p-3 overflow-x-auto border border-slate-700"><pre class="text-xs font-mono text-slate-400 whitespace-pre"><code>${escapeHtml(finding.context_lines)}</code></pre></div></div>` : ''}

                            ${finding.recommendation ? `<div class="bg-slate-900/50 border border-slate-700 rounded p-3"><p class="text-slate-500 text-xs font-mono mb-1">FIX:</p><p class="text-slate-400 text-xs leading-relaxed">${escapeHtml(finding.recommendation)}</p></div>` : ''}
                        </div>
                    </div>
                `;

                findingsList.appendChild(findingElement);
            });
        } else {
            noFindings.classList.remove('hidden');
        }
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

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });
});
