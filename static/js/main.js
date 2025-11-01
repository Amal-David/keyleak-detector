document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('urlInput');
    const scanButton = document.getElementById('scanButton');
    const buttonText = document.getElementById('buttonText');
    const buttonSpinner = document.getElementById('buttonSpinner');
    const resultsSection = document.getElementById('results');
    const findingsList = document.getElementById('findingsList');
    const noFindings = document.getElementById('noFindings');
    const errorMessage = document.getElementById('errorMessage');
    const errorText = document.getElementById('errorText');
    const scanSummary = document.getElementById('scanSummary');
    const scanUrl = document.getElementById('scanUrl');

    scanButton.addEventListener('click', startScan);
    urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            startScan();
        }
    });

    function startScan() {
        const url = urlInput.value.trim();
        if (!url) {
            showError('Please enter a URL to scan');
            return;
        }

        // Validate URL format
        if (!url.match(/^https?:\/\/.+/)) {
            showError('Please enter a valid URL starting with http:// or https://');
            return;
        }

        // Reset UI
        setLoading(true);
        clearResults();
        hideError();

        // Make API request
        fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
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
            // Scroll to results
            resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        })
        .catch(error => {
            showError(error.message || 'An error occurred while scanning the URL');
            console.error('Error:', error);
        })
        .finally(() => {
            setLoading(false);
        });
    }

    function setLoading(isLoading) {
        if (isLoading) {
            scanButton.disabled = true;
            buttonText.textContent = 'SCANNING...';
            buttonSpinner.classList.remove('hidden');
            scanButton.classList.remove('hover:bg-emerald-500');
        } else {
            scanButton.disabled = false;
            buttonText.textContent = 'SCAN';
            buttonSpinner.classList.add('hidden');
            scanButton.classList.add('hover:bg-emerald-500');
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
        
        // Update scan URL
        if (data.url) {
            scanUrl.textContent = data.url;
        }
        
        // Update scan summary
        if (data.scan_summary) {
            const { total_findings, critical_severity, high_severity, medium_severity, low_severity } = data.scan_summary;
            
            if (total_findings === 0) {
                noFindings.classList.remove('hidden');
                return;
            }
            
            scanSummary.innerHTML = `
                <div class="flex flex-wrap gap-2 font-mono text-xs">
                    <div class="bg-slate-900/80 px-3 py-1 rounded border border-slate-600">
                        <span class="text-emerald-400">${total_findings}</span>
                        <span class="text-slate-500 ml-1">total</span>
                    </div>
                    ${critical_severity > 0 ? `
                        <div class="bg-red-900/30 px-3 py-1 rounded border border-red-700">
                            <span class="text-red-400">${critical_severity}</span>
                            <span class="text-red-500 ml-1">crit</span>
                        </div>
                    ` : ''}
                    ${high_severity > 0 ? `
                        <div class="bg-red-900/20 px-3 py-1 rounded border border-red-800">
                            <span class="text-red-400">${high_severity}</span>
                            <span class="text-red-500 ml-1">high</span>
                        </div>
                    ` : ''}
                    ${medium_severity > 0 ? `
                        <div class="bg-yellow-900/20 px-3 py-1 rounded border border-yellow-800">
                            <span class="text-yellow-400">${medium_severity}</span>
                            <span class="text-yellow-500 ml-1">med</span>
                        </div>
                    ` : ''}
                    ${low_severity > 0 ? `
                        <div class="bg-blue-900/20 px-3 py-1 rounded border border-blue-800">
                            <span class="text-blue-400">${low_severity}</span>
                            <span class="text-blue-500 ml-1">low</span>
                        </div>
                    ` : ''}
                </div>
            `;
        }

        // Add findings to the list
        if (data.findings && data.findings.length > 0) {
            data.findings.forEach((finding, index) => {
                const findingElement = document.createElement('div');
                findingElement.className = `p-6 finding-card severity-${finding.severity}`;
                findingElement.style.animationDelay = `${index * 0.05}s`;
                findingElement.classList.add('fade-in');
                
                // Get severity indicator
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
                
                // Format type
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
                            
                            ${finding.source ? `
                                <div class="text-xs font-mono">
                                    <span class="text-slate-500">SOURCE:</span>
                                    <span class="text-slate-400 ml-2">${escapeHtml(finding.source)}</span>
                                </div>
                            ` : ''}
                            
                            ${finding.line ? `
                                <div class="text-xs font-mono">
                                    <span class="text-slate-500">LINE:</span>
                                    <span class="text-slate-400 ml-2">${finding.line}</span>
                                </div>
                            ` : ''}
                            
                            ${finding.context_lines ? `
                                <div>
                                    <p class="text-slate-500 text-xs font-mono mb-1">CONTEXT:</p>
                                    <div class="bg-slate-900 rounded p-3 overflow-x-auto border border-slate-700">
                                        <pre class="text-xs font-mono text-slate-400 whitespace-pre"><code>${escapeHtml(finding.context_lines)}</code></pre>
                                    </div>
                                </div>
                            ` : ''}
                            
                            ${finding.recommendation ? `
                                <div class="bg-slate-900/50 border border-slate-700 rounded p-3">
                                    <p class="text-slate-500 text-xs font-mono mb-1">FIX:</p>
                                    <p class="text-slate-400 text-xs leading-relaxed">${escapeHtml(finding.recommendation)}</p>
                                </div>
                            ` : ''}
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
        
        // Auto-hide after 10 seconds
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

    // Smooth scroll for anchor links
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

