import subprocess
import sys
import os
import socket
import shutil
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"

RESULTS_DIR = "rto3_results"
os.makedirs(RESULTS_DIR, exist_ok=True)
logging.basicConfig(filename=f"{RESULTS_DIR}/rto3.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def validate_target(target):
    try:
        socket.gethostbyname(target)
        return True
    except:
        print(f"{RED}[-] Invalid target or DNS resolution failed.{RESET}")
        return False

def check_tool(tool):
    if shutil.which(tool) is None:
        print(f"{RED}[-] {tool} not installed. Skipping.{RESET}")
        return False
    return True

def detect_services(target):
    print(f"{CYAN}[*] Auto-detecting services...{RESET}")
    try:
        r = subprocess.run(["nmap","-p80,443,389,445,88,9200","--open","-T4",target],capture_output=True,text=True,timeout=45)
        out = r.stdout.lower()
        d = []
        if any(x in out for x in ["80/tcp","443/tcp"]): d.append("WEB")
        if any(x in out for x in ["389/tcp","445/tcp"]): d.append("AD")
        if "9200/tcp" in out: d.append("ES")
        return d
    except:
        return []

def save_output(tool,target,cmd,output,start,code):
    dur = time.time()-start
    logging.info(f"{tool} on {target} | {dur:.1f}s | code={code}")
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    path = f"{RESULTS_DIR}/{tool}_{target.replace('.','_')}_{ts}.txt"
    with open(path,"w",encoding="utf-8") as f:
        f.write(f"Tool: {tool}\nTarget: {target}\nCmd: {' '.join(cmd)}\nTime: {dur:.2f}s\nExit: {code}\n\n{output}")
    print(f"{GREEN}[+] Saved {tool}{RESET}")

def general_recon(target):
    if not check_tool("nmap"): return
    print(f"{YELLOW}[*] General Recon...{RESET}")
    s=time.time()
    cmd=["nmap","-sV","-sC","-O",target]
    try:
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=300)
        save_output("general",target,cmd,r.stdout+r.stderr,s,r.returncode)
    except: pass

def ldap_enum(target):
    if not check_tool("ldapsearch"): return
    print(f"{YELLOW}[*] LDAP Enum...{RESET}")
    s=time.time()
    cmd=["ldapsearch","-H",f"ldap://{target}","-x","-s","base","(objectclass=*)"]
    try:
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
        save_output("ldap",target,cmd,r.stdout+r.stderr,s,r.returncode)
    except: pass

def smb_enum(target):
    if not check_tool("smbclient"): return
    print(f"{YELLOW}[*] SMB Enum...{RESET}")
    s=time.time()
    cmd=["smbclient","-L",target,"-N"]
    try:
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
        save_output("smb",target,cmd,r.stdout+r.stderr,s,r.returncode)
    except: pass

def kerberos_enum(target):
    print(f"{YELLOW}[*] Kerberos (manual){RESET}")
    logging.info(f"Kerberos manual on {target}")

def bloodhound_collect(target):
    print(f"{YELLOW}[*] BloodHound (manual){RESET}")
    logging.info(f"BloodHound manual on {target}")

def nmap_web(target):
    if not check_tool("nmap"): return
    print(f"{YELLOW}[*] Web Nmap...{RESET}")
    s=time.time()
    cmd=["nmap","-sV","--script=http-title,http-enum","-p80,443,8080",target]
    try:
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=180)
        save_output("nmap_web",target,cmd,r.stdout+r.stderr,s,r.returncode)
    except: pass

def whatweb(target):
    if not check_tool("whatweb"): return
    print(f"{YELLOW}[*] WhatWeb...{RESET}")
    s=time.time()
    cmd=["whatweb",target]
    try:
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=60)
        save_output("whatweb",target,cmd,r.stdout+r.stderr,s,r.returncode)
    except: pass

def nikto(target):
    if not check_tool("nikto"): return
    print(f"{YELLOW}[*] Nikto...{RESET}")
    s=time.time()
    cmd=["nikto","-h",f"http://{target}"]
    try:
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=300)
        save_output("nikto",target,cmd,r.stdout+r.stderr,s,r.returncode)
    except: pass

def gobuster(target):
    if not check_tool("gobuster"): return
    print(f"{YELLOW}[*] Gobuster...{RESET}")
    s=time.time()
    wl="/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(wl): wl="/usr/share/seclists/Discovery/Web-Content/common.txt"
    cmd=["gobuster","dir","-u",f"http://{target}","-w",wl,"-q","-t","50"]
    try:
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=120)
        save_output("gobuster",target,cmd,r.stdout+r.stderr,s,r.returncode)
    except: pass

def wafw00f(target):
    if not check_tool("wafw00f"): return
    print(f"{YELLOW}[*] WafW00f...{RESET}")
    s=time.time()
    cmd=["wafw00f",f"http://{target}"]
    try:
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=60)
        save_output("wafw00f",target,cmd,r.stdout+r.stderr,s,r.returncode)
    except: pass

def es_version(target):
    if not check_tool("curl"): return
    print(f"{YELLOW}[*] ES Version...{RESET}")
    s=time.time()
    cmd=["curl","-s",f"http://{target}:9200"]
    try:
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=10)
        save_output("es_version",target,cmd,r.stdout+r.stderr,s,r.returncode)
    except: pass

def es_ports(target):
    if not check_tool("nmap"): return
    print(f"{YELLOW}[*] ES Ports...{RESET}")
    s=time.time()
    cmd=["nmap","-p9200,9300",target]
    try:
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
        save_output("es_ports",target,cmd,r.stdout+r.stderr,s,r.returncode)
    except: pass

def es_endpoints(target):
    if not check_tool("curl"): return
    print(f"{YELLOW}[*] ES Endpoints...{RESET}")
    s=time.time()
    cmd=["curl","-s",f"http://{target}:9200/_cat/indices"]
    try:
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=10)
        save_output("es_endpoints",target,cmd,r.stdout+r.stderr,s,r.returncode)
    except: pass

def run_profile(target, profile):
    print(f"{BLUE}[*] Running {profile.upper()} profile (parallel)...{RESET}")
    logging.info(f"Profile {profile} started")
    pmap = {
        "stealth": [general_recon, ldap_enum, smb_enum, es_ports],
        "full_web": [nmap_web, whatweb, nikto, gobuster, wafw00f],
        "full_ad": [ldap_enum, smb_enum, kerberos_enum, bloodhound_collect],
        "full_es": [es_version, es_ports, es_endpoints],
        "all": [general_recon, ldap_enum, smb_enum, kerberos_enum, bloodhound_collect, nmap_web, whatweb, nikto, gobuster, wafw00f, es_version, es_ports, es_endpoints]
    }
    funcs = pmap.get(profile, [])
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = [ex.submit(f, target) for f in funcs]
        for future in as_completed(futures):
            try: future.result()
            except: pass
    print(f"{GREEN}[+] {profile.upper()} completed.{RESET}")

def generate_html_report(target):
    print(f"{BLUE}[*] Generating rich HTML report...{RESET}")
    logging.info("HTML report generated")
    files = sorted([f for f in os.listdir(RESULTS_DIR) if f.endswith(".txt") and "rto3.log" not in f])
    html = f"""<html><head><title>RTO3 Report - {target}</title>
<style>body{{font-family:monospace;background:#111;color:#0f0;}} details{{margin:10px;border:1px solid #333;padding:10px;}} summary{{cursor:pointer;color:{BLUE};font-weight:bold;}} pre{{background:#222;padding:10px;overflow:auto;}}</style></head><body>
<h1 style="color:{GREEN}">RTO3 Report - {target}</h1><p>Generated: {datetime.now()}</p>"""
    for f in files:
        with open(f"{RESULTS_DIR}/{f}","r",encoding="utf-8") as ff:
            content = ff.read()[:4000].replace("<","&lt;")
        html += f'<details><summary>{f.split("_")[0].upper()}</summary><pre>{content}</pre></details>'
    html += "</body></html>"
    path = f"{RESULTS_DIR}/REPORT_{target.replace('.','_')}.html"
    with open(path,"w",encoding="utf-8") as f: f.write(html)
    print(f"{GREEN}[+] Report saved: {path}{RESET}")

def main():
    target = input(f"\n{YELLOW}Enter target IP/hostname: {RESET}").strip()
    if not target or not validate_target(target):
        sys.exit(1)
    detected = detect_services(target)
    if detected:
        print(f"{GREEN}[+] Detected: {' + '.join(detected)}{RESET}")

    while True:
        print(f"\n{BLUE}=== RTO3 Offensive Security Toolkit ==={RESET}")
        print("1. General Recon")
        print("2. Active Directory")
        print("3. Web Server")
        print("4. ElasticSearch")
        print(f"{CYAN}5. Run Profile{RESET}")
        print("6. Generate HTML Report")
        print("7. Exit")
        opt = input(f"{YELLOW}Choose: {RESET}").strip()

        if opt == "1": general_recon(target)
        elif opt == "2":
            while True:
                print(f"\n{BLUE}--- Active Directory ---{RESET}")
                print("1. LDAP\n2. SMB\n3. Kerberos\n4. BloodHound\n5. Back")
                s = input(f"{YELLOW}Choose: {RESET}").strip()
                if s=="1": ldap_enum(target)
                elif s=="2": smb_enum(target)
                elif s=="3": kerberos_enum(target)
                elif s=="4": bloodhound_collect(target)
                elif s=="5": break
        elif opt == "3":
            while True:
                print(f"\n{BLUE}--- Web Server ---{RESET}")
                print("1. Nmap\n2. WhatWeb\n3. Nikto\n4. Gobuster\n5. WafW00f\n6. Back")
                s = input(f"{YELLOW}Choose: {RESET}").strip()
                if s=="1": nmap_web(target)
                elif s=="2": whatweb(target)
                elif s=="3": nikto(target)
                elif s=="4": gobuster(target)
                elif s=="5": wafw00f(target)
                elif s=="6": break
        elif opt == "4":
            while True:
                print(f"\n{BLUE}--- ElasticSearch ---{RESET}")
                print("1. Version\n2. Ports\n3. Endpoints\n4. Back")
                s = input(f"{YELLOW}Choose: {RESET}").strip()
                if s=="1": es_version(target)
                elif s=="2": es_ports(target)
                elif s=="3": es_endpoints(target)
                elif s=="4": break
        elif opt == "5":
            print(f"\n{CYAN}Profiles:{RESET}\n1. Stealth\n2. Full Web\n3. Full AD\n4. Full ES\n5. Everything")
            p = input(f"{YELLOW}Choose profile: {RESET}").strip()
            pmap = {"1":"stealth","2":"full_web","3":"full_ad","4":"full_es","5":"all"}
            if p in pmap: run_profile(target, pmap[p])
        elif opt == "6": generate_html_report(target)
        elif opt == "7":
            print(f"{GREEN}Exiting...{RESET}")
            break

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print(f"\n{RED}[!] Exited.{RESET}")