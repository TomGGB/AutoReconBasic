#!/bin/bash

#═══════════════════════════════════════════════════════════════
#  Auto Recon Script - Automated Bug Bounty Reconnaissance
#═══════════════════════════════════════════════════════════════
#
#  Usage: ./auto_recon.sh domain.com
#
#  This script automates the complete reconnaissance workflow:
#  1. Subdomain enumeration
#  2. Live host detection
#  3. JavaScript file extraction
#  4. Endpoint discovery
#  5. Vulnerability scanning
#  6. Report generation
#
#═══════════════════════════════════════════════════════════════

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
banner() {
    echo -e "${CYAN}"
    cat << "EOF"
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║           AUTO RECON - Bug Bounty Edition            ║
    ║              Automated Reconnaissance                 ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Progress bar
progress() {
    local current=$1
    local total=$2
    local task=$3
    local percent=$((current * 100 / total))
    local filled=$((percent / 2))
    local empty=$((50 - filled))

    printf "\r${BLUE}[${GREEN}"
    printf "%${filled}s" | tr ' ' '█'
    printf "${NC}"
    printf "%${empty}s" | tr ' ' '░'
    printf "${BLUE}]${NC} ${percent}%% - ${task}"
}

# Logger
log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_error() {
    echo -e "${RED}[!]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check if domain provided
if [ $# -eq 0 ]; then
    banner
    echo -e "${RED}Error: No domain provided${NC}"
    echo ""
    echo "Usage: $0 <domain>"
    echo "Example: $0 google.com"
    echo ""
    exit 1
fi

DOMAIN=$1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
WORKDIR="${DOMAIN}_recon_${TIMESTAMP}"

banner

log_info "Target: ${GREEN}${DOMAIN}${NC}"
log_info "Timestamp: ${TIMESTAMP}"
log_info "Working directory: ${WORKDIR}"
echo ""

# Create working directory
mkdir -p "${WORKDIR}"/{subdomains,alive,js,endpoints,vulnerabilities,reports}
cd "${WORKDIR}"

# Tools check
log_info "Checking required tools..."
TOOLS=("subfinder" "httpx" "katana" "waybackurls" "nuclei")
MISSING_TOOLS=()

for tool in "${TOOLS[@]}"; do
    if ! command -v $tool &> /dev/null; then
        MISSING_TOOLS+=($tool)
    fi
done

if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    log_error "Missing tools: ${MISSING_TOOLS[*]}"
    log_warning "Install missing tools or script will skip those steps"
    echo ""
fi

# Start reconnaissance
START_TIME=$(date +%s)

echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}         PHASE 1: SUBDOMAIN ENUMERATION                ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""

# Subfinder
if command -v subfinder &> /dev/null; then
    log_info "Running subfinder..."
    subfinder -d "${DOMAIN}" -all -recursive -silent -o subdomains/subfinder.txt 2>/dev/null &
    SUBFINDER_PID=$!
else
    log_warning "subfinder not found, skipping..."
    SUBFINDER_PID=""
fi

# Wait for subfinder with progress
if [ -n "$SUBFINDER_PID" ]; then
    while kill -0 $SUBFINDER_PID 2>/dev/null; do
        if [ -f subdomains/subfinder.txt ]; then
            COUNT=$(wc -l < subdomains/subfinder.txt 2>/dev/null || echo 0)
            printf "\r${BLUE}[*]${NC} Subfinder running... Found: ${GREEN}${COUNT}${NC} subdomains"
        fi
        sleep 1
    done
    echo ""
    COUNT=$(wc -l < subdomains/subfinder.txt 2>/dev/null || echo 0)
    log_success "Subfinder complete: ${COUNT} subdomains"
fi

echo ""

# Combine and deduplicate
log_info "Combining and deduplicating subdomains..."
cat subdomains/*.txt 2>/dev/null | sort -u > subdomains/all_subdomains.txt
TOTAL_SUBS=$(wc -l < subdomains/all_subdomains.txt)
log_success "Total unique subdomains: ${GREEN}${TOTAL_SUBS}${NC}"

# Filter critical subdomains if applicable
log_info "Filtering critical patterns (api*, app*, admin*, etc.)..."
cat subdomains/all_subdomains.txt | grep -iE "^(api|app|admin|dev|test|stage|staging|qa|vpn|internal|git|gitlab|jenkins)" > subdomains/critical_subs.txt 2>/dev/null || touch subdomains/critical_subs.txt
CRITICAL_COUNT=$(wc -l < subdomains/critical_subs.txt)
log_success "Critical subdomains: ${GREEN}${CRITICAL_COUNT}${NC}"

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}         PHASE 2: LIVE HOST DETECTION                  ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""

# Check alive hosts
if command -v httpx &> /dev/null; then
    log_info "Probing for alive hosts with httpx..."

    cat subdomains/all_subdomains.txt | httpx \
        -silent \
        -timeout 10 \
        -threads 50 \
        -status-code \
        -title \
        -tech-detect \
        -follow-redirects \
        -o alive/httpx_full.txt &

    HTTPX_PID=$!

    # Show progress
    while kill -0 $HTTPX_PID 2>/dev/null; do
        if [ -f alive/httpx_full.txt ]; then
            COUNT=$(wc -l < alive/httpx_full.txt 2>/dev/null || echo 0)
            PERCENT=$((COUNT * 100 / TOTAL_SUBS))
            printf "\r${BLUE}[*]${NC} httpx running... Alive: ${GREEN}${COUNT}${NC}/${TOTAL_SUBS} (${PERCENT}%%)"
        fi
        sleep 1
    done
    echo ""

    # Extract just URLs
    cat alive/httpx_full.txt | awk '{print $1}' > alive/alive_hosts.txt
    ALIVE_COUNT=$(wc -l < alive/alive_hosts.txt)
    log_success "Alive hosts: ${GREEN}${ALIVE_COUNT}${NC}"
else
    log_warning "httpx not found, skipping alive check..."
    cp subdomains/all_subdomains.txt alive/alive_hosts.txt
    ALIVE_COUNT=$TOTAL_SUBS
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}         PHASE 3: JAVASCRIPT FILE EXTRACTION           ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""

# Extract JS files with katana
if command -v katana &> /dev/null; then
    log_info "Crawling for JavaScript files..."

    # Crawl top 20 alive hosts (to save time)
    head -20 alive/alive_hosts.txt | katana \
        -jc \
        -d 3 \
        -silent \
        -ef woff,woff2,ttf,eot,svg,png,jpg,jpeg,gif,css \
        -o endpoints/katana_all.txt 2>/dev/null &

    KATANA_PID=$!

    # Show progress
    while kill -0 $KATANA_PID 2>/dev/null; do
        if [ -f endpoints/katana_all.txt ]; then
            COUNT=$(wc -l < endpoints/katana_all.txt 2>/dev/null || echo 0)
            printf "\r${BLUE}[*]${NC} Katana crawling... Found: ${GREEN}${COUNT}${NC} URLs"
        fi
        sleep 1
    done
    echo ""

    # Extract JS files
    cat endpoints/katana_all.txt | grep "\.js$" | sort -u > js/js_files.txt 2>/dev/null || touch js/js_files.txt
    JS_COUNT=$(wc -l < js/js_files.txt)
    log_success "JavaScript files: ${GREEN}${JS_COUNT}${NC}"
else
    log_warning "katana not found, skipping JS extraction..."
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}         PHASE 4: WAYBACK MACHINE ENUMERATION          ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""

# Wayback URLs
if command -v waybackurls &> /dev/null; then
    log_info "Fetching historical URLs from Wayback Machine..."

    waybackurls "${DOMAIN}" 2>/dev/null | tee endpoints/wayback_all.txt | head -1 > /dev/null &
    WAYBACK_PID=$!

    while kill -0 $WAYBACK_PID 2>/dev/null; do
        if [ -f endpoints/wayback_all.txt ]; then
            COUNT=$(wc -l < endpoints/wayback_all.txt 2>/dev/null || echo 0)
            printf "\r${BLUE}[*]${NC} Wayback URLs... Found: ${GREEN}${COUNT}${NC} URLs"
        fi
        sleep 1
    done
    echo ""

    WAYBACK_COUNT=$(wc -l < endpoints/wayback_all.txt)
    log_success "Wayback URLs: ${GREEN}${WAYBACK_COUNT}${NC}"

    # Extract interesting endpoints
    log_info "Filtering interesting endpoints..."
    cat endpoints/wayback_all.txt | grep -iE "\.(txt|log|cache|secret|db|backup|yml|json|gz|rar|zip|config|env|sql)$" > endpoints/sensitive_files.txt 2>/dev/null || touch endpoints/sensitive_files.txt
    cat endpoints/wayback_all.txt | grep "\.js$" >> js/js_files.txt 2>/dev/null || true
    cat endpoints/wayback_all.txt | grep -iE "(api|v[0-9]|auth|login|admin|portal)" > endpoints/api_endpoints.txt 2>/dev/null || touch endpoints/api_endpoints.txt

    SENSITIVE_COUNT=$(wc -l < endpoints/sensitive_files.txt)
    API_COUNT=$(wc -l < endpoints/api_endpoints.txt)
    log_success "Sensitive files: ${GREEN}${SENSITIVE_COUNT}${NC}, API endpoints: ${GREEN}${API_COUNT}${NC}"
else
    log_warning "waybackurls not found, skipping..."
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}         PHASE 5: VULNERABILITY SCANNING               ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""

# Nuclei scanning
if command -v nuclei &> /dev/null; then
    log_info "Running nuclei vulnerability scans..."

    # Subdomain takeover check
    log_info "Checking for subdomain takeovers..."
    cat alive/alive_hosts.txt | nuclei \
        -t ~/nuclei-templates/http/takeovers/ \
        -silent \
        -o vulnerabilities/takeovers.txt 2>/dev/null || touch vulnerabilities/takeovers.txt
    TAKEOVER_COUNT=$(wc -l < vulnerabilities/takeovers.txt)
    log_success "Subdomain takeover results: ${GREEN}${TAKEOVER_COUNT}${NC}"

    # Exposures check
    log_info "Checking for exposed files and configurations..."
    cat alive/alive_hosts.txt | nuclei \
        -t ~/nuclei-templates/http/exposures/ \
        -silent \
        -rl 150 \
        -o vulnerabilities/exposures.txt 2>/dev/null &

    NUCLEI_PID=$!
    while kill -0 $NUCLEI_PID 2>/dev/null; do
        if [ -f vulnerabilities/exposures.txt ]; then
            COUNT=$(wc -l < vulnerabilities/exposures.txt 2>/dev/null || echo 0)
            printf "\r${BLUE}[*]${NC} Nuclei scanning... Found: ${GREEN}${COUNT}${NC} issues"
        fi
        sleep 2
    done
    echo ""

    EXPOSURE_COUNT=$(wc -l < vulnerabilities/exposures.txt)
    log_success "Exposure results: ${GREEN}${EXPOSURE_COUNT}${NC}"

    # CVE check (high/critical only)
    log_info "Checking for known CVEs (this may take a while)..."
    cat alive/alive_hosts.txt | nuclei \
        -t ~/nuclei-templates/http/cves/ \
        -severity critical,high \
        -silent \
        -rl 100 \
        -o vulnerabilities/cves.txt 2>/dev/null || touch vulnerabilities/cves.txt
    CVE_COUNT=$(wc -l < vulnerabilities/cves.txt)
    log_success "CVE results: ${GREEN}${CVE_COUNT}${NC}"
else
    log_warning "nuclei not found, skipping vulnerability scanning..."
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}         PHASE 6: REPORT GENERATION                    ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""

# Generate report
log_info "Generating reconnaissance report..."

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
MINUTES=$((DURATION / 60))
SECONDS=$((DURATION % 60))

# Create markdown report
cat > reports/recon_report.md << EOF
# Reconnaissance Report - ${DOMAIN}

**Date:** $(date)
**Duration:** ${MINUTES}m ${SECONDS}s
**Target:** ${DOMAIN}

---

## Executive Summary

Automated reconnaissance completed on **${DOMAIN}** using the following methodology:
1. Subdomain enumeration
2. Live host detection
3. JavaScript and endpoint discovery
4. Historical data analysis (Wayback Machine)
5. Vulnerability scanning

---

## Statistics

| Category | Count |
|----------|-------|
| **Total Subdomains** | ${TOTAL_SUBS} |
| **Critical Subdomains** | ${CRITICAL_COUNT} |
| **Alive Hosts** | ${ALIVE_COUNT} |
| **JavaScript Files** | ${JS_COUNT:-0} |
| **Wayback URLs** | ${WAYBACK_COUNT:-0} |
| **Sensitive Files** | ${SENSITIVE_COUNT:-0} |
| **API Endpoints** | ${API_COUNT:-0} |
| **Subdomain Takeovers** | ${TAKEOVER_COUNT:-0} |
| **Exposures Found** | ${EXPOSURE_COUNT:-0} |
| **CVEs Found** | ${CVE_COUNT:-0} |

---

## Critical Subdomains

\`\`\`
$(head -20 subdomains/critical_subs.txt 2>/dev/null || echo "None found")
\`\`\`

---

## Alive Hosts (Top 20)

\`\`\`
$(head -20 alive/alive_hosts.txt 2>/dev/null)
\`\`\`

---

## Potential Vulnerabilities

### Subdomain Takeovers
\`\`\`
$(cat vulnerabilities/takeovers.txt 2>/dev/null || echo "None found")
\`\`\`

### Exposures
\`\`\`
$(head -10 vulnerabilities/exposures.txt 2>/dev/null || echo "None found")
\`\`\`

### CVEs
\`\`\`
$(cat vulnerabilities/cves.txt 2>/dev/null || echo "None found")
\`\`\`

---

## Sensitive Files Discovered

\`\`\`
$(head -20 endpoints/sensitive_files.txt 2>/dev/null || echo "None found")
\`\`\`

---

## API Endpoints (Top 20)

\`\`\`
$(head -20 endpoints/api_endpoints.txt 2>/dev/null || echo "None found")
\`\`\`

---

## JavaScript Files (Top 20)

\`\`\`
$(head -20 js/js_files.txt 2>/dev/null || echo "None found")
\`\`\`

---

## Directory Structure

\`\`\`
${WORKDIR}/
├── subdomains/
│   ├── all_subdomains.txt     (${TOTAL_SUBS} subdomains)
│   └── critical_subs.txt      (${CRITICAL_COUNT} critical)
├── alive/
│   └── alive_hosts.txt        (${ALIVE_COUNT} hosts)
├── js/
│   └── js_files.txt           (${JS_COUNT:-0} files)
├── endpoints/
│   ├── wayback_all.txt        (${WAYBACK_COUNT:-0} URLs)
│   ├── sensitive_files.txt    (${SENSITIVE_COUNT:-0} files)
│   └── api_endpoints.txt      (${API_COUNT:-0} endpoints)
├── vulnerabilities/
│   ├── takeovers.txt          (${TAKEOVER_COUNT:-0} issues)
│   ├── exposures.txt          (${EXPOSURE_COUNT:-0} issues)
│   └── cves.txt               (${CVE_COUNT:-0} CVEs)
└── reports/
    └── recon_report.md        (this file)
\`\`\`

---

## Next Steps

1. **Manual Verification**
   - Verify subdomain takeover findings
   - Check exposed sensitive files
   - Validate CVEs and exposures

2. **Deep Dive Analysis**
   - Analyze JavaScript files for API endpoints
   - Test authentication flows
   - Check for IDORs and authorization issues

3. **Exploit Development**
   - Create PoCs for confirmed vulnerabilities
   - Document reproduction steps
   - Prepare bug bounty reports

---

## Tools Used

- subfinder - Subdomain enumeration
- httpx - HTTP probing and detection
- katana - Web crawling and JS extraction
- waybackurls - Historical URL discovery
- nuclei - Vulnerability scanning

---

**Report generated by Auto Recon Script**
EOF

log_success "Report generated: reports/recon_report.md"

# Create text summary
cat > reports/summary.txt << EOF
═══════════════════════════════════════════════════════════════
            RECONNAISSANCE SUMMARY - ${DOMAIN}
═══════════════════════════════════════════════════════════════

Date: $(date)
Duration: ${MINUTES}m ${SECONDS}s

STATISTICS:
-----------
Total Subdomains:       ${TOTAL_SUBS}
Critical Subdomains:    ${CRITICAL_COUNT}
Alive Hosts:            ${ALIVE_COUNT}
JavaScript Files:       ${JS_COUNT:-0}
Wayback URLs:           ${WAYBACK_COUNT:-0}
Sensitive Files:        ${SENSITIVE_COUNT:-0}
API Endpoints:          ${API_COUNT:-0}

VULNERABILITIES:
----------------
Subdomain Takeovers:    ${TAKEOVER_COUNT:-0}
Exposures:              ${EXPOSURE_COUNT:-0}
CVEs:                   ${CVE_COUNT:-0}

FILES LOCATION:
---------------
Working Directory: ${WORKDIR}/

KEY FILES:
- subdomains/all_subdomains.txt
- alive/alive_hosts.txt
- endpoints/api_endpoints.txt
- vulnerabilities/*.txt
- reports/recon_report.md

═══════════════════════════════════════════════════════════════
EOF

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}         RECONNAISSANCE COMPLETE!                       ${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""

# Display summary
cat reports/summary.txt

echo ""
log_success "All results saved in: ${CYAN}${WORKDIR}/${NC}"
log_success "View report: ${CYAN}cat ${WORKDIR}/reports/recon_report.md${NC}"
echo ""

# Quick findings
if [ "$TAKEOVER_COUNT" -gt 0 ] || [ "$CVE_COUNT" -gt 0 ]; then
    echo -e "${RED}⚠️  CRITICAL FINDINGS DETECTED! ⚠️${NC}"
    echo ""
    [ "$TAKEOVER_COUNT" -gt 0 ] && echo -e "${RED}[!]${NC} Potential subdomain takeovers: ${TAKEOVER_COUNT}"
    [ "$CVE_COUNT" -gt 0 ] && echo -e "${RED}[!]${NC} Known CVEs found: ${CVE_COUNT}"
    echo ""
    log_warning "Review vulnerabilities/ directory immediately!"
fi

echo -e "${CYAN}Happy hunting! 🎯${NC}"
echo ""
