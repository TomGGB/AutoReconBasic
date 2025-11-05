let currentPhase = 0;
let scanInterval = null;
let currentJobId = null;
let currentDetailedData = {};

// Elements - will be initialized after DOM loads
let domainInput, startBtn, statusSection, progressSection, resultsSection;
let logSection, logContent, statusContent;
let modal, modalTitle, modalData, modalSearch, modalClose, modalCopy, modalDownload;

function startRecon() {
    const domain = domainInput.value.trim();

    if (!domain) {
        alert('Please enter a domain');
        return;
    }

    // Validate domain format
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
        alert('Please enter a valid domain (e.g., example.com)');
        return;
    }

    // Disable input
    domainInput.disabled = true;
    startBtn.disabled = true;

    // Show sections
    statusSection.classList.remove('hidden');
    progressSection.classList.remove('hidden');
    logSection.classList.remove('hidden');
    resultsSection.classList.add('hidden');

    // Reset UI
    resetUI();

    // Add initial log
    addLog('info', `Starting reconnaissance for ${domain}...`);

    // Start the scan
    fetch('/api/start', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ domain: domain })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            addLog('success', 'Scan initiated successfully');
            updateStatus('Running', 'loading');

            // Start polling for progress
            scanInterval = setInterval(() => pollProgress(data.job_id), 2000);
        } else {
            addLog('error', `Failed to start scan: ${data.error}`);
            updateStatus('Failed', 'error');
            resetControls();
        }
    })
    .catch(error => {
        addLog('error', `Error: ${error.message}`);
        updateStatus('Error', 'error');
        resetControls();
    });
}

function pollProgress(jobId) {
    fetch(`/api/status/${jobId}`)
        .then(response => response.json())
        .then(data => {
            if (data.phase) {
                updatePhase(data.phase);
            }

            if (data.logs) {
                data.logs.forEach(log => {
                    addLog(log.type, log.message);
                });
            }

            if (data.status === 'completed') {
                clearInterval(scanInterval);
                updateStatus('Completado', 'success');
                addLog('success', 'Reconocimiento completado!');
                currentJobId = jobId;
                showResults(data.results);
                resetControls();
            } else if (data.status === 'failed') {
                clearInterval(scanInterval);
                updateStatus('Failed', 'error');
                addLog('error', 'Scan failed. Check logs for details.');
                resetControls();
            }
        })
        .catch(error => {
            console.error('Polling error:', error);
        });
}

function updatePhase(phase) {
    if (phase > currentPhase) {
        // Mark previous phases as completed
        for (let i = 1; i <= currentPhase; i++) {
            const phaseElement = document.querySelector(`.phase[data-phase="${i}"]`);
            if (phaseElement) {
                phaseElement.classList.remove('active');
                phaseElement.classList.add('completed');
            }
        }

        // Mark current phase as active
        currentPhase = phase;
        const currentPhaseElement = document.querySelector(`.phase[data-phase="${phase}"]`);
        if (currentPhaseElement) {
            currentPhaseElement.classList.add('active');
        }
    }
}

function updateStatus(status, type) {
    statusContent.innerHTML = `
        <div class="status-item">
            <div class="status-icon ${type}"></div>
            <span>${status}</span>
        </div>
    `;
}

function addLog(type, message) {
    const logLine = document.createElement('div');
    logLine.className = `log-line ${type}`;

    const timestamp = new Date().toLocaleTimeString();
    const prefix = {
        'info': '[*]',
        'success': '[+]',
        'error': '[!]',
        'warning': '[!]'
    }[type] || '[~]';

    logLine.textContent = `[${timestamp}] ${prefix} ${message}`;
    logContent.appendChild(logLine);
    logContent.scrollTop = logContent.scrollHeight;
}

function showResults(results) {
    resultsSection.classList.remove('hidden');

    // Update stats
    document.getElementById('totalSubs').textContent = results.total_subs || 0;
    document.getElementById('criticalSubs').textContent = results.critical_subs || 0;
    document.getElementById('aliveHosts').textContent = results.alive_hosts || 0;
    document.getElementById('jsFiles').textContent = results.js_files || 0;
    document.getElementById('waybackUrls').textContent = results.wayback_urls || 0;
    document.getElementById('apiEndpoints').textContent = results.api_endpoints || 0;

    // Update vulnerabilities
    document.getElementById('takeovers').textContent = results.takeovers || 0;
    document.getElementById('cves').textContent = results.cves || 0;
    document.getElementById('exposures').textContent = results.exposures || 0;

    // Update report path
    const reportPath = document.getElementById('reportPath');
    reportPath.textContent = `Results saved in: ${results.workdir}`;

    // View report button
    const viewReportBtn = document.getElementById('viewReportBtn');
    viewReportBtn.onclick = () => {
        window.open(`/api/report/${results.job_id}`, '_blank');
    };

    // Animate counters
    animateCounters();
}

function animateCounters() {
    const counters = document.querySelectorAll('.stat-value, .vuln-count');
    counters.forEach(counter => {
        const target = parseInt(counter.textContent);
        const duration = 1000;
        const step = target / (duration / 16);
        let current = 0;

        const timer = setInterval(() => {
            current += step;
            if (current >= target) {
                counter.textContent = target;
                clearInterval(timer);
            } else {
                counter.textContent = Math.floor(current);
            }
        }, 16);
    });
}

function resetUI() {
    currentPhase = 0;
    logContent.innerHTML = '';

    // Reset all phases
    const phases = document.querySelectorAll('.phase');
    phases.forEach(phase => {
        phase.classList.remove('active', 'completed');
    });

    // Reset stats
    const stats = document.querySelectorAll('.stat-value, .vuln-count');
    stats.forEach(stat => stat.textContent = '0');
}

function resetControls() {
    domainInput.disabled = false;
    startBtn.disabled = false;
}

// Handle page visibility
document.addEventListener('visibilitychange', () => {
    if (document.hidden && scanInterval) {
        // Don't clear interval, keep polling in background
    }
});

// Initialize everything when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Initialize elements
    domainInput = document.getElementById('domain');
    startBtn = document.getElementById('startBtn');
    statusSection = document.getElementById('statusSection');
    progressSection = document.getElementById('progressSection');
    resultsSection = document.getElementById('resultsSection');
    logSection = document.getElementById('logSection');
    logContent = document.getElementById('logContent');
    statusContent = document.getElementById('statusContent');

    modal = document.getElementById('detailsModal');
    modalTitle = document.getElementById('modalTitle');
    modalData = document.getElementById('modalData');
    modalSearch = document.getElementById('modalSearch');
    modalClose = document.querySelector('.modal-close');
    modalCopy = document.getElementById('modalCopy');
    modalDownload = document.getElementById('modalDownload');

    // Event Listeners
    startBtn.addEventListener('click', startRecon);
    domainInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') startRecon();
    });

    // Close modal on click outside or close button
    modalClose.addEventListener('click', closeModal);
    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeModal();
    });

    // ESC key to close modal
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && !modal.classList.contains('hidden')) {
            closeModal();
        }
    });

    // Search functionality
    modalSearch.addEventListener('input', (e) => {
        filterModalData(e.target.value);
    });

    // Copy all data to clipboard
    modalCopy.addEventListener('click', () => {
        const text = currentDetailedData.join('\n');
        navigator.clipboard.writeText(text).then(() => {
            const originalText = modalCopy.textContent;
            modalCopy.textContent = 'Copiado!';
            setTimeout(() => {
                modalCopy.textContent = originalText;
            }, 2000);
        }).catch(err => {
            console.error('Error copying:', err);
            alert('Error al copiar al portapapeles');
        });
    });

    // Download data as text file
    modalDownload.addEventListener('click', () => {
        const text = currentDetailedData.join('\n');
        const blob = new Blob([text], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${modalTitle.textContent.replace(/\s+/g, '_')}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    });

    // Click handlers for cards
    const clickableCards = document.querySelectorAll('.clickable');
    clickableCards.forEach(card => {
        card.addEventListener('click', () => {
            const type = card.getAttribute('data-type');
            openModal(type);
        });
    });

    // Initial message
    addLog('info', 'Listo para iniciar el reconocimiento');
    updateStatus('Listo', 'success');
});

function openModal(type) {
    if (!currentJobId) {
        alert('No hay datos disponibles todavía');
        return;
    }

    // Set title based on type
    const titles = {
        'subdomains': 'Todos los Subdominios',
        'critical': 'Subdominios Críticos',
        'alive': 'Hosts Vivos',
        'js': 'Archivos JavaScript',
        'wayback': 'URLs de Wayback Machine',
        'api': 'Endpoints de API',
        'takeovers': 'Subdomain Takeovers',
        'cves': 'CVEs Encontrados',
        'exposures': 'Exposures Encontradas'
    };

    modalTitle.textContent = titles[type] || type;
    modalSearch.value = '';

    // Fetch detailed data
    fetch(`/api/details/${currentJobId}/${type}`)
        .then(response => response.json())
        .then(data => {
            if (data.data && data.data.length > 0) {
                currentDetailedData = data.data;
                displayModalData(data.data);
            } else {
                modalData.innerHTML = '<div class="modal-data-empty">No se encontraron resultados</div>';
            }
            modal.classList.remove('hidden');
        })
        .catch(error => {
            console.error('Error fetching details:', error);
            modalData.innerHTML = '<div class="modal-data-empty">Error al cargar los datos</div>';
            modal.classList.remove('hidden');
        });
}

function displayModalData(data) {
    if (!data || data.length === 0) {
        modalData.innerHTML = '<div class="modal-data-empty">No se encontraron resultados</div>';
        return;
    }

    modalData.innerHTML = data.map(item =>
        `<div class="modal-data-item">${item}</div>`
    ).join('');
}

function filterModalData(searchTerm) {
    if (!searchTerm) {
        displayModalData(currentDetailedData);
        return;
    }

    const filtered = currentDetailedData.filter(item =>
        item.toLowerCase().includes(searchTerm.toLowerCase())
    );
    displayModalData(filtered);
}

function closeModal() {
    modal.classList.add('hidden');
    currentDetailedData = {};
    modalSearch.value = '';
}
