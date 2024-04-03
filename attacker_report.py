#!/bin/python3.6
# Joey Guarino
# April 2024

from geoip import geolite2
import subprocess as sp
import sys
import re

MIN_COUNT = 10

# runs a command and returns the result
def run(cmd) -> str:
    proc = sp.Popen(cmd, shell=True, stdout=sp.PIPE, stderr=sp.DEVNULL)
    return str(proc.stdout.read())[2:-3]

def proc_log(path):
    failed_ips = []
    try:
        with open(path) as file:
            ip_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
            for line in file:
                if "Failed" in line:
                    ip = ip_pattern.search(line)[0]
                    failed_ips.append(ip)
    except:
        print(f"Error reading from file {file}")
        exit(1)
    return failed_ips

def sort_key(item):
    return item[0]

def main(args):
    run("clear")
    if len(args) != 2:
        if len(args) < 2:
            path = input("Enter logfile path: ")
        else:
            print(f"[Error]\nUsage: attacker_report <path_to_logfile>")
    else:
        path = args[1]
    print(f"Processing {path}...")
    failed_ips_raw = proc_log(path)
    ips = set(failed_ips_raw)
    entries = []
    for ip in ips:
        count = 0
        country = geolite2.lookup(ip)
        if country is not None:
            country = country.country
        else:
            country = "UNKNOWN"
        for raw_ip in failed_ips_raw:
            if raw_ip == ip:
                count += 1
        entries.append((count, ip, country))
    entries.sort(key=sort_key)
    cur_date = run("date")
    print(f"\n Report - {cur_date}\n------------------------------------------")
    print("  Count\tIP\t\tCountry")
    for entry in entries:
        if entry[0] >= MIN_COUNT:
            print(f"  {entry[0]}\t{entry[1]}\t{entry[2]}")
    

if __name__ =="__main__":
    main(sys.argv)