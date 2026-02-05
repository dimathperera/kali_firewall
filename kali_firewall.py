#!/usr/bin/env python3
# Kali Linux Firewall using nftables (STABLE VERSION)

import json
import subprocess
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

RULES_FILE = "firewall_rules.json"
NFT_SAVE_FILE = "/etc/nftables.conf"


class Firewall:

    def __init__(self):
        self.rules = self.load_rules()
        self.init_nftables()
        self.apply_saved_rules()

    # ---------- LOW LEVEL ----------
    def nft(self, ruleset: str):
        subprocess.run(
            ["nft", "-f", "-"],
            input=ruleset.encode(),
            check=False
        )

    # ---------- INIT NFTABLES ----------
    def init_nftables(self):
        ruleset = """
flush ruleset

table inet firewall {
    chain input {
        type filter hook input priority 0;
        policy drop;

        iifname "lo" accept
        ct state established,related accept
    }

    chain forward {
        type filter hook forward priority 0;
        policy drop;
    }

    chain output {
        type filter hook output priority 0;
        policy accept;
    }
}
"""
        self.nft(ruleset)

    # ---------- STORAGE ----------
    def load_rules(self):
        try:
            with open(RULES_FILE, "r") as f:
                return json.load(f)
        except:
            return []

    def save_rules(self):
        with open(RULES_FILE, "w") as f:
            json.dump(self.rules, f, indent=2)

    # ---------- RULE HANDLING ----------
    def build_rule(self, rule):
        line = "add rule inet firewall input"

        if rule.get("src_ip"):
            line += f" ip saddr {rule['src_ip']}"

        if rule.get("dst_ip"):
            line += f" ip daddr {rule['dst_ip']}"

        proto = rule.get("proto")
        port = rule.get("dst_port")

        if proto in ("tcp", "udp"):
            line += f" {proto}"
            if port:
                line += f" dport {port}"

        line += f" {rule['action']}"
        return line

    def add_rule(self, rule):
        self.rules.append(rule)
        self.nft(self.build_rule(rule))
        self.save_rules()

    def apply_saved_rules(self):
        for rule in self.rules:
            self.nft(self.build_rule(rule))

    # ---------- LOGGING ----------
    def log_packet(self, pkt):
        if IP not in pkt:
            return

        src = pkt[IP].src
        dst = pkt[IP].dst

        if TCP in pkt:
            print(f"[TCP] {src}:{pkt[TCP].sport} → {dst}:{pkt[TCP].dport}")
        elif UDP in pkt:
            print(f"[UDP] {src}:{pkt[UDP].sport} → {dst}:{pkt[UDP].dport}")
        else:
            print(f"[IP]  {src} → {dst}")


# ---------- UI ----------
def menu():
    print("""
==============================
 Kali Linux Python Firewall
==============================
1. Block traffic
2. Allow traffic
3. Show rules
4. Monitor traffic
5. Save & Exit
==============================
""")


def create_rule(action):
    rule = {"action": "accept" if action == "allow" else "drop"}

    src = input("Source IP (enter = any): ").strip()
    dst = input("Destination IP (enter = any): ").strip()
    proto = input("Protocol (tcp/udp/any): ").strip().lower()

    rule["src_ip"] = src or None
    rule["dst_ip"] = dst or None

    if proto in ("tcp", "udp"):
        rule["proto"] = proto
        port = input("Destination port (enter = any): ").strip()
        rule["dst_port"] = port or None
    else:
        rule["proto"] = None
        rule["dst_port"] = None

    fw.add_rule(rule)
    print("✔ Rule added\n")


def packet_handler(pkt):
    fw.log_packet(pkt)


# ---------- MAIN ----------
if __name__ == "__main__":
    fw = Firewall()

    while True:
        menu()
        c = input("Select: ").strip()

        if c == "1":
            create_rule("block")
        elif c == "2":
            create_rule("allow")
        elif c == "3":
            subprocess.run(["nft", "list", "ruleset"])
        elif c == "4":
            print("Monitoring traffic (CTRL+C to stop)")
            sniff(prn=packet_handler, store=False)
        elif c == "5":
            subprocess.run(
                f"nft list ruleset > {NFT_SAVE_FILE}",
                shell=True
            )
            print("Saved. Bye ")
            break
        else:
            print("Invalid option\n")
