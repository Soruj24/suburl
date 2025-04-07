#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "  ____  _____ ____  _____ ____  _   _ ___ ____ _____ ____  "  
echo " |  _ \| ____|  _ \| ____/ ___|| | | |_ _/ ___| ____|  _ \ "
echo " | |_) |  _| | |_) |  _| \___ \| |_| || | |   |  _| | |_) |"
echo " |  _ <| |___|  _ <| |___ ___) |  _  || | |___| |___|  _ < "
echo " |_| \_\_____|_| \_\_____|____/|_| |_|___\____|_____|_| \_\\"
echo -e "${NC}"
echo " Advanced Reconnaissance Script v2.0"
echo " Author: Security Researcher"
echo -e "============================================\n"

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
required_tools=("subfinder" "assetfinder" "findomain" "httpx" "dnsx" "subzy" "gau" "waybackurls" "nuclei" "gf")
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
mkdir -p "$dir"/{subdomains,urls,fuzzing,vulnerabilities,github,secrets,report,screenshots}

echo -e "${BLUE}[*] Starting reconnaissance on ${domain}...${NC}"
echo -e "${GREEN}[✓] Output will be saved to: ${dir}${NC}"

# Step 1: Subdomain Enumeration (without amass)
echo -e "${BLUE}[1] 🔍 Subdomain Enumeration...${NC}"
{
    echo -e "${BLUE}   [+] Running subfinder...${NC}"
    subfinder -d "$domain" -o "$dir/subdomains/subfinder.txt" -silent
    
    echo -e "${BLUE}   [+] Running assetfinder...${NC}"
    assetfinder --subs-only "$domain" > "$dir/subdomains/assetfinder.txt"
    
    echo -e "${BLUE}   [+] Running findomain...${NC}"
    findomain -t "$domain" -q -o > /dev/null && mv "$domain.txt" "$dir/subdomains/findomain.txt"
    
    echo -e "${BLUE}   [+] Running crt.sh...${NC}"
    curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > "$dir/subdomains/crtsh.txt"
    
    # Combine and sort subdomains
    cat "$dir"/subdomains/*.txt | sort -u > "$dir/subdomains/all_subs.txt"
    sub_count=$(wc -l < "$dir/subdomains/all_subs.txt")
    echo -e "${GREEN}[✓] Found ${sub_count} unique subdomains.${NC}"
} 2>/dev/null

# Step 2: DNS Resolution & Live Host Check
echo -e "${BLUE}[2] 🌐 Resolving DNS and Checking Live Hosts...${NC}"
{
    dnsx -l "$dir/subdomains/all_subs.txt" -silent -o "$dir/subdomains/resolved.txt"
    
    # Enhanced httpx with more information
    httpx -l "$dir/subdomains/resolved.txt" -silent \
        -title -tech-detect -status-code -content-length \
        -o "$dir/subdomains/live_subs.txt" -json > "$dir/subdomains/live_subs.json"
    
    live_count=$(wc -l < "$dir/subdomains/live_subs.txt")
    echo -e "${GREEN}[✓] Found ${live_count} live hosts.${NC}"
    
    # Take screenshots of live hosts
    if command -v gowitness &> /dev/null; then
        echo -e "${BLUE}   [+] Taking screenshots...${NC}"
        gowitness file -f "$dir/subdomains/live_subs.txt" -P "$dir/screenshots" --disable-logging
    fi
} 2>/dev/null

# Step 3: Subdomain Takeover Check
echo -e "${BLUE}[3] ⚠️ Checking for Subdomain Takeover...${NC}"
{
    subzy run --targets "$dir/subdomains/live_subs.txt" > "$dir/subdomains/takeover_results.txt"
    echo -e "${GREEN}[✓] Takeover check completed.${NC}"
} 2>/dev/null

# Step 4: URL Collection
echo -e "${BLUE}[4] 📚 Collecting URLs...${NC}"
{
    echo -e "${BLUE}   [+] Running gau...${NC}"
    gau "$domain" > "$dir/urls/gau.txt"
    
    echo -e "${BLUE}   [+] Running waybackurls...${NC}"
    cat "$dir/subdomains/all_subs.txt" | waybackurls > "$dir/urls/wayback.txt"
    
    # Additional URL sources
    echo -e "${BLUE}   [+] Running katana (if available)...${NC}"
    if command -v katana &> /dev/null; then
        katana -list "$dir/subdomains/live_subs.txt" -jc -kf all -d 3 -silent -o "$dir/urls/katana.txt"
    fi
    
    # Combine all URLs
    cat "$dir/urls/gau.txt" "$dir/urls/wayback.txt" "$dir/urls/katana.txt" 2>/dev/null | sort -u > "$dir/urls/all_urls.txt"
    url_count=$(wc -l < "$dir/urls/all_urls.txt")
    echo -e "${GREEN}[✓] Collected ${url_count} URLs.${NC}"
} 2>/dev/null

# Step 5: JS Recon
echo -e "${BLUE}[5] 📦 Collecting and Analyzing JS Files...${NC}"
{
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
} 2>/dev/null

# Step 6: GF Pattern Scanning (Optimized)
echo -e "${BLUE}[6] 🔎 Running GF Pattern Scanning...${NC}"
{
    gf_patterns=("xss" "sqli" "lfi" "ssrf" "idor" "rce" "redirect" "ssjs" "ssti" "debug_logic" "cors" "jwt" "aws-keys" "s3-buckets" "firebase" "upload-fields" "secrets" "api-keys" "tokens")
    mkdir -p "$dir/vulnerabilities/gf_scan"

    for pattern in "${gf_patterns[@]}"; do
        echo -e "${BLUE}   [+] Checking for ${pattern}...${NC}"
        cat "$dir/urls/all_urls.txt" | gf "$pattern" > "$dir/vulnerabilities/gf_scan/${pattern}.txt"
    done
    echo -e "${GREEN}[✓] GF pattern scanning completed.${NC}"
} 2>/dev/null

# Step 7: Nuclei Scanning (Comprehensive)
echo -e "${BLUE}[7] 🚀 Running Nuclei Vulnerability Scanning...${NC}"
{
    echo -e "${BLUE}   [+] Running quick scans first...${NC}"
    nuclei -l "$dir/subdomains/live_subs.txt" \
        -t ~/nuclei-templates/cves/ \
        -t ~/nuclei-templates/vulnerabilities/ \
        -t ~/nuclei-templates/misconfiguration/ \
        -o "$dir/vulnerabilities/nuclei_quick_scan.txt" -silent
    
    echo -e "${BLUE}   [+] Running comprehensive scans...${NC}"
    nuclei -l "$dir/subdomains/live_subs.txt" \
        -t ~/nuclei-templates/ \
        -severity medium,high,critical \
        -o "$dir/vulnerabilities/nuclei_full_scan.txt" -silent
    
    echo -e "${GREEN}[✓] Nuclei scanning completed.${NC}"
} 2>/dev/null

# Step 8: GitHub Recon (if gitrob is available)
echo -e "${BLUE}[8] 🐙 Checking for GitHub Recon...${NC}"
{
    if command -v gitrob &> /dev/null; then
        echo -e "${BLUE}   [+] Running gitrob...${NC}"
        gitrob "$domain" -o "$dir/github/gitrob_results.json" -silent
    else
        echo -e "${YELLOW}[!] gitrob not found. Skipping GitHub recon.${NC}"
    fi
} 2>/dev/null

# Step 9: Generate Comprehensive Report
echo -e "${BLUE}[9] 📊 Generating Report...${NC}"
{
    echo "Advanced Reconnaissance Report for ${domain}"
    echo "Generated on: $(date)"
    echo "======================================"
    echo ""
    echo "=== Executive Summary ==="
    echo "Total subdomains found: ${sub_count}"
    echo "Live hosts: ${live_count}"
    echo "URLs collected: ${url_count}"
    if [ "$js_count" -gt 0 ]; then
        echo "JS files found: ${js_count}"
    fi
    echo ""
    echo "=== Critical Findings ==="
    grep -E "high|critical" "$dir/vulnerabilities/nuclei_quick_scan.txt" | head -n 5
    echo ""
    echo "=== Potential Vulnerabilities ==="
    echo "GF Pattern Matches:"
    for pattern in "${gf_patterns[@]}"; do
        count=$(wc -l < "$dir/vulnerabilities/gf_scan/${pattern}.txt" 2>/dev/null || echo 0)
        echo "  ${pattern}: ${count}"
    done
    echo ""
    echo "Nuclei Findings:"
    echo "  Quick Scan: $(wc -l < "$dir/vulnerabilities/nuclei_quick_scan.txt")"
    echo "  Full Scan: $(wc -l < "$dir/vulnerabilities/nuclei_full_scan.txt")"
    echo ""
    echo "=== Subdomain Takeover ==="
    grep -q "VULNERABLE" "$dir/subdomains/takeover_results.txt" && echo "Vulnerable subdomains found!" || echo "No subdomain takeovers detected."
    echo ""
    echo "=== Secrets ==="
    if [ -f "$dir/secrets/js_secrets.txt" ]; then
        echo "Potential secrets found in JS: $(grep -c "SECRET" "$dir/secrets/js_secrets.txt" || echo 0)"
    fi
    if [ -f "$dir/github/gitrob_results.json" ]; then
        echo "GitHub secrets found: $(jq '.Results | length' "$dir/github/gitrob_results.json")"
    fi
    echo ""
    echo "=== Next Steps ==="
    echo "1. Review critical findings in nuclei_quick_scan.txt"
    echo "2. Check GF pattern matches for potential vulnerabilities"
    echo "3. Investigate any subdomain takeover possibilities"
    echo "4. Examine secrets found in JS files and GitHub"
    echo "5. Review all screenshots in the screenshots directory"
} > "$dir/report/summary.txt"

# Create a zip archive of the results
echo -e "${BLUE}[*] Creating archive of results...${NC}"
zip -r "$dir.zip" "$dir" > /dev/null
echo -e "${GREEN}[✓] Archive created: ${dir}.zip${NC}"

echo -e "${GREEN}"
echo "============================================"
echo " RECONNAISSANCE COMPLETED SUCCESSFULLY!"
echo "============================================"
echo -e "${NC}"
echo -e " Final report: ${dir}/report/summary.txt"
echo -e " All results: ${dir}.zip"
echo -e " Total execution time: $SECONDS seconds"
