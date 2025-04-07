#!/bin/bash

# ---------------------- Colors ---------------------- #
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ---------------------- Banner ---------------------- #
echo -e "${BLUE}"
echo "   █████╗ ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗██████╗  "
echo "  ██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔══██╗ "
echo "  ███████║██████╔╝██║   ██║███████║██╔██╗ ██║██║  ██║ "
echo "  ██╔══██║██╔═══╝ ██║   ██║██╔══██║██║╚██╗██║██║  ██║ "
echo "  ██║  ██║██║     ╚██████╔╝██║  ██║██║ ╚████║██████╔╝ "
echo "  ╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝  "
echo -e "${NC}"
echo " Advanced Bug Bounty Recon v2.1 - Full Automation Script"
echo " Author: Security Researcher | Language: Bash"
echo "============================================================"

# ---------------------- Root Check ---------------------- #
if [[ $EUID -ne 0 ]]; then
  echo -e "${YELLOW}[!] Run as root for better results (some tools need it).${NC}"
fi

# ---------------------- Dependency Check ---------------------- #
check_dep() {
  command -v "$1" &>/dev/null || { echo -e "${RED}[X] $1 is not installed!${NC}"; exit 1; }
}

TOOLS=(subfinder assetfinder findomain dnsx httpx gau waybackurls gauplus ffuf nuclei gf naabu arjun getJS qsreplace unzip jq)
echo -e "${BLUE}[*] Checking dependencies...${NC}"
for tool in "${TOOLS[@]}"; do
  check_dep "$tool"
done

echo -e "${GREEN}[✓] All dependencies are installed.${NC}"

# ---------------------- Input Domain ---------------------- #
if [ -z "$1" ]; then
  echo -e "${RED}Usage: $0 <domain.com>${NC}"
  exit 1
fi

DOMAIN=$1
TS=$(date +"%Y%m%d_%H%M%S")
OUTDIR="recon_${DOMAIN}_${TS}"
mkdir -p "$OUTDIR"/{subdomains,live,urls,vulns,js,params,screenshots,secrets,report,ports,archive}
echo -e "${GREEN}[+] Output Directory: $OUTDIR${NC}"

# ---------------------- Subdomain Enumeration ---------------------- #
echo -e "${BLUE}[1] Subdomain Enumeration...${NC}"
subfinder -d "$DOMAIN" -all -silent -o "$OUTDIR/subdomains/subfinder.txt"
assetfinder --subs-only "$DOMAIN" > "$OUTDIR/subdomains/assetfinder.txt"
findomain -t "$DOMAIN" -q -o > /dev/null && mv "$DOMAIN.txt" "$OUTDIR/subdomains/findomain.txt"
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > "$OUTDIR/subdomains/crtsh.txt"
cat "$OUTDIR/subdomains/"*.txt | sort -u > "$OUTDIR/subdomains/all.txt"
echo -e "${GREEN}[✓] Total Subdomains: $(wc -l < "$OUTDIR/subdomains/all.txt")${NC}"

# ---------------------- DNS Resolution & Live Hosts ---------------------- #
echo -e "${BLUE}[2] DNS Resolving & Live Checking...${NC}"
dnsx -l "$OUTDIR/subdomains/all.txt" -silent -o "$OUTDIR/live/resolved.txt"
httpx -l "$OUTDIR/live/resolved.txt" -silent -title -tech-detect -status-code -content-length -json > "$OUTDIR/live/live.json"
cat "$OUTDIR/live/live.json" | jq -r '.url' > "$OUTDIR/live/live.txt"
echo -e "${GREEN}[✓] Live Hosts: $(wc -l < "$OUTDIR/live/live.txt")${NC}"

# ---------------------- Port Scanning ---------------------- #
echo -e "${BLUE}[3] Port Scanning with Naabu...${NC}"
# Convert URLs to hostnames for Naabu
cat "$OUTDIR/live/live.txt" | sed -E 's#https?://##;s#/.*##' | sort -u > "$OUTDIR/ports/naabu_targets.txt"
naabu -list "$OUTDIR/ports/naabu_targets.txt" -top-ports 100 -silent -o "$OUTDIR/ports/naabu_ports.txt" 2>/dev/null || echo -e "${YELLOW}[!] Naabu port scan failed or no open ports found${NC}"

# ---------------------- Subdomain Takeover ---------------------- #
if command -v subzy &>/dev/null; then
  echo -e "${BLUE}[4] Subdomain Takeover Check (Subzy)...${NC}"
  subzy run --targets "$OUTDIR/live/live.txt" --hide_fails > "$OUTDIR/vulns/subzy_takeover.txt"
else
  echo -e "${YELLOW}[!] Subzy not installed, skipping takeover check${NC}"
fi

# ---------------------- URL Collection ---------------------- #
echo -e "${BLUE}[5] Gathering URLs (gau, waybackurls, gauplus)...${NC}"
# Create empty gau config file to prevent warning
touch ~/.gau.toml
gau "$DOMAIN" > "$OUTDIR/urls/gau.txt" 2>/dev/null
cat "$OUTDIR/subdomains/all.txt" | waybackurls > "$OUTDIR/urls/wayback.txt" 2>/dev/null
gauplus -f "$OUTDIR/live/live.txt" > "$OUTDIR/urls/gauplus.txt" 2>/dev/null

# Optional: waymore for deeper crawling
if command -v waymore &>/dev/null; then
  waymore -i "$DOMAIN" -mode U -o "$OUTDIR/urls/waymore.txt"
fi

cat "$OUTDIR/urls/"*.txt | sort -u > "$OUTDIR/urls/all.txt"
echo -e "${GREEN}[✓] Total URLs: $(wc -l < "$OUTDIR/urls/all.txt")${NC}"

# ---------------------- JavaScript Recon ---------------------- #
echo -e "${BLUE}[6] JavaScript Recon...${NC}"
getJS --input "$OUTDIR/live/live.txt" --output "$OUTDIR/js/jsfiles.txt" 2>/dev/null
cat "$OUTDIR/js/jsfiles.txt" | grep ".js" | sort -u > "$OUTDIR/js/final_js.txt"

# ---------------------- JS Secrets & Endpoints ---------------------- #
echo -e "${BLUE}[7] Analyzing JS for secrets...${NC}"
if [ -f "LinkFinder.py" ] && [ -f "SecretFinder.py" ]; then
  mkdir -p "$OUTDIR/js/analysis"
  while read -r jsurl; do
    python3 LinkFinder.py -i "$jsurl" -o cli >> "$OUTDIR/js/analysis/endpoints.txt" 2>/dev/null
    python3 SecretFinder.py -i "$jsurl" -o cli >> "$OUTDIR/secrets/js_secrets.txt" 2>/dev/null
  done < "$OUTDIR/js/final_js.txt"
else
  echo -e "${YELLOW}[!] LinkFinder or SecretFinder not found.${NC}"
fi

# ---------------------- GF Pattern Scanning ---------------------- #
echo -e "${BLUE}[8] GF Pattern Scanning...${NC}"
gf_patterns=(xss sqli ssrf idor rce lfi redirect ssti debug_logic cors)
mkdir -p "$OUTDIR/vulns/gf"
for pattern in "${gf_patterns[@]}"; do
  cat "$OUTDIR/urls/all.txt" | gf "$pattern" > "$OUTDIR/vulns/gf/${pattern}.txt"
done

# ---------------------- Parameter Discovery ---------------------- #
echo -e "${BLUE}[9] Discovering Hidden Parameters...${NC}"
arjun -i "$OUTDIR/live/live.txt" -t 50 -oT "$OUTDIR/params/arjun.txt" 2>/dev/null || echo -e "${YELLOW}[!] Arjun parameter scan failed${NC}"

# ---------------------- Nuclei Vulnerability Scanning ---------------------- #
echo -e "${BLUE}[10] Nuclei Scanning...${NC}"
nuclei -l "$OUTDIR/live/live.txt" -t ~/nuclei-templates/ -severity medium,high,critical -o "$OUTDIR/vulns/nuclei.txt" -silent 2>/dev/null

# ---------------------- Reporting ---------------------- #
echo -e "${BLUE}[✓] Generating Summary Report...${NC}"
echo "Recon Summary for: $DOMAIN" > "$OUTDIR/report/summary.txt"
echo "Live Hosts: $(wc -l < "$OUTDIR/live/live.txt")" >> "$OUTDIR/report/summary.txt"
echo "Total URLs: $(wc -l < "$OUTDIR/urls/all.txt")" >> "$OUTDIR/report/summary.txt"
echo "Subdomains: $(wc -l < "$OUTDIR/subdomains/all.txt")" >> "$OUTDIR/report/summary.txt"
echo "Ports Found: $(wc -l < "$OUTDIR/ports/naabu_ports.txt" 2>/dev/null || echo 0)" >> "$OUTDIR/report/summary.txt"
echo "Potential Takeovers: $(grep -i 'vulnerable' "$OUTDIR/vulns/subzy_takeover.txt" 2>/dev/null | wc -l)" >> "$OUTDIR/report/summary.txt"
echo "Nuclei Criticals: $(grep -i 'critical' "$OUTDIR/vulns/nuclei.txt" 2>/dev/null | wc -l)" >> "$OUTDIR/report/summary.txt"

# ---------------------- Archive ---------------------- #
echo -e "${BLUE}[*] Zipping output...${NC}"
zip -qr "$OUTDIR.zip" "$OUTDIR"
echo -e "${GREEN}[✓] Recon Completed. Archive: $OUTDIR.zip${NC}"
echo -e "${GREEN}[✓] Final Report: $OUTDIR/report/summary.txt${NC}"
