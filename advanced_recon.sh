#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}[!] Running as non-root user. Some checks might require root privileges.${NC}"
fi

# Dependency check function
check_dependency() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}[X] Error: $1 not found. Please install it before running this script.${NC}"
        exit 1
    fi
}

# Check for required tools
echo -e "${BLUE}[*] Checking dependencies...${NC}"
required_tools=("subfinder" "assetfinder" "amass" "findomain" "httpx" "dnsx" "subzy" "gau" "waybackurls" "nuclei" "gf")
for tool in "${required_tools[@]}"; do
    check_dependency "$tool"
done
echo -e "${GREEN}[✓] All required tools are installed.${NC}"

# Argument check
if [ -z "$1" ]; then
    echo -e "${RED}[X] Usage: ./advanced_recon.sh <domain.com>${NC}"
    exit 1
fi

domain=$1
timestamp=$(date +"%Y%m%d_%H%M%S")
dir="recon_${domain}_${timestamp}"
mkdir -p "$dir"/{subdomains,urls,fuzzing,vulnerabilities,github,secrets,report}

echo -e "${BLUE}[*] Starting reconnaissance on ${domain}...${NC}"
echo -e "${GREEN}[✓] Output will be saved to: ${dir}${NC}"

# Step 1: Subdomain Enumeration
echo -e "${BLUE}[1] 🔍 Subdomain Enumeration...${NC}"
{
    subfinder -d "$domain" -o "$dir/subdomains/subfinder.txt" -silent
    assetfinder --subs-only "$domain" > "$dir/subdomains/assetfinder.txt"
    amass enum -passive -d "$domain" -o "$dir/subdomains/amass.txt"
    findomain -t "$domain" -q -o > /dev/null && mv "$domain.txt" "$dir/subdomains/findomain.txt"
} 2>/dev/null

# Combine and sort subdomains
cat "$dir"/subdomains/*.txt | sort -u > "$dir/subdomains/all_subs.txt"
sub_count=$(wc -l < "$dir/subdomains/all_subs.txt")
echo -e "${GREEN}[✓] Found ${sub_count} unique subdomains.${NC}"

# Step 2: DNS Resolution & Live Host Check
echo -e "${BLUE}[2] 🌐 Resolving DNS and Checking Live Hosts...${NC}"
dnsx -l "$dir/subdomains/all_subs.txt" -silent -o "$dir/subdomains/resolved.txt"
httpx -l "$dir/subdomains/resolved.txt" -silent -o "$dir/subdomains/live_subs.txt"
live_count=$(wc -l < "$dir/subdomains/live_subs.txt")
echo -e "${GREEN}[✓] Found ${live_count} live hosts.${NC}"

# Step 3: Subdomain Takeover Check
echo -e "${BLUE}[3] ⚠️ Checking for Subdomain Takeover...${NC}"
subzy run --targets "$dir/subdomains/live_subs.txt" > "$dir/subdomains/takeover_results.txt"
echo -e "${GREEN}[✓] Takeover check completed.${NC}"

# Step 4: URL Collection
echo -e "${BLUE}[4] 📚 Collecting URLs...${NC}"
gau "$domain" > "$dir/urls/gau.txt"
cat "$dir/subdomains/all_subs.txt" | waybackurls > "$dir/urls/wayback.txt"
cat "$dir/urls/gau.txt" "$dir/urls/wayback.txt" | sort -u > "$dir/urls/all_urls.txt"
url_count=$(wc -l < "$dir/urls/all_urls.txt")
echo -e "${GREEN}[✓] Collected ${url_count} URLs.${NC}"

# Step 5: JS Recon
echo -e "${BLUE}[5] 📦 Collecting and Analyzing JS Files...${NC}"
if command -v getJS &> /dev/null; then
    getJS --input "$dir/subdomains/live_subs.txt" --output "$dir/urls/jsfiles.txt"
    js_count=$(wc -l < "$dir/urls/jsfiles.txt")
    echo -e "${GREEN}[✓] Found ${js_count} JS files.${NC}"
    
    # Process JS files if any were found
    if [ "$js_count" -gt 0 ]; then
        # Check for LinkFinder and SecretFinder
        if [ -f "LinkFinder.py" ] && [ -f "SecretFinder.py" ]; then
            echo -e "${BLUE}   [+] Running LinkFinder and SecretFinder...${NC}"
            mkdir -p "$dir/urls/js_analysis"
            while read -r url; do
                domain_name=$(echo "$url" | awk -F/ '{print $3}')
                python3 LinkFinder.py -i "$url" -o cli >> "$dir/urls/js_analysis/${domain_name}_endpoints.txt"
                python3 SecretFinder.py -i "$url" -o cli >> "$dir/secrets/js_secrets.txt"
            done < "$dir/urls/jsfiles.txt"
        else
            echo -e "${YELLOW}[!] LinkFinder.py or SecretFinder.py not found. Skipping advanced JS analysis.${NC}"
        fi
        
        # Run nuclei on JS files
        echo -e "${BLUE}   [+] Running Nuclei on JS files...${NC}"
        nuclei -l "$dir/urls/jsfiles.txt" -t ~/nuclei-templates/exposures/ -o "$dir/vulnerabilities/nuclei_js_exposure.txt" -silent
    fi
else
    echo -e "${YELLOW}[!] getJS not found. Skipping JS file collection.${NC}"
fi

# Step 6: GF Pattern Scanning (Optimized)
echo -e "${BLUE}[6] 🔎 Running GF Pattern Scanning...${NC}"
gf_patterns=("xss" "sqli" "lfi" "ssrf" "idor" "rce" "redirect" "ssjs" "ssti" "debug_logic" "cors" "jwt" "aws-keys" "s3-buckets" "firebase" "upload-fields" "secrets" "api-keys" "tokens")
mkdir -p "$dir/vulnerabilities/gf_scan"

for pattern in "${gf_patterns[@]}"; do
    echo -e "${BLUE}   [+] Checking for ${pattern}...${NC}"
    cat "$dir/urls/all_urls.txt" | gf "$pattern" > "$dir/vulnerabilities/gf_scan/${pattern}.txt"
done
echo -e "${GREEN}[✓] GF pattern scanning completed.${NC}"

# Step 7: Nuclei Scanning
echo -e "${BLUE}[7] 🚀 Running Nuclei Vulnerability Scanning...${NC}"
nuclei -l "$dir/subdomains/live_subs.txt" -t ~/nuclei-templates/ -o "$dir/vulnerabilities/nuclei_scan.txt" -silent
echo -e "${GREEN}[✓] Nuclei scanning completed.${NC}"

# Step 8: GitHub Recon (if gitrob is available)
echo -e "${BLUE}[8] 🐙 Checking for GitHub Recon...${NC}"
if command -v gitrob &> /dev/null; then
    echo -e "${BLUE}   [+] Running gitrob...${NC}"
    gitrob "$domain" -o "$dir/github/gitrob_results.json" -silent
else
    echo -e "${YELLOW}[!] gitrob not found. Skipping GitHub recon.${NC}"
fi

# Step 9: Generate Report
echo -e "${BLUE}[9] 📊 Generating Report...${NC}"
{
    echo "Reconnaissance Report for ${domain}"
    echo "Generated on: $(date)"
    echo "======================================"
    echo ""
    echo "=== Subdomains ==="
    echo "Total subdomains found: ${sub_count}"
    echo "Live hosts: ${live_count}"
    echo ""
    echo "=== URLs ==="
    echo "Total URLs collected: ${url_count}"
    if [ "$js_count" -gt 0 ]; then
        echo "JS files found: ${js_count}"
    fi
    echo ""
    echo "=== Potential Vulnerabilities ==="
    echo "GF Pattern Matches:"
    for pattern in "${gf_patterns[@]}"; do
        count=$(wc -l < "$dir/vulnerabilities/gf_scan/${pattern}.txt" 2>/dev/null || echo 0)
        echo "  ${pattern}: ${count}"
    done
    echo ""
    echo "Nuclei Findings: $(wc -l < "$dir/vulnerabilities/nuclei_scan.txt")"
    echo ""
    echo "=== Subdomain Takeover ==="
    grep -q "VULNERABLE" "$dir/subdomains/takeover_results.txt" && echo "Vulnerable subdomains found!" || echo "No subdomain takeovers detected."
    echo ""
    echo "=== Secrets ==="
    if [ -f "$dir/secrets/js_secrets.txt" ]; then
        echo "Potential secrets found in JS: $(grep -c "SECRET" "$dir/secrets/js_secrets.txt" || echo 0)"
    fi
} > "$dir/report/summary.txt"

echo -e "${GREEN}[✓] Report generated: ${dir}/report/summary.txt${NC}"
echo -e "${GREEN}[✓] Reconnaissance completed successfully!${NC}" 
