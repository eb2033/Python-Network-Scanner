#!/usr/bin/python3

import nmap
import os
import json
scanner = nmap.PortScanner()

#Changed the ladder of elifs to a function with the match statement
def pickoption(choice):
    match choice:
        case "1":
            if "-sS" in options:
                options.add("--top-ports 100")
            else:
                options.add("-sS")
                options.add("--top-ports 100")

        case "2":
            if "-sS" in options:
                options.add("-p-")
            else:
                options.add("-sS")
                options.add("-p-")

        case "3":
            if "-sS" in options:
                options.add("-sV")
            else:
                options.add("-sS ")
                options.add("-sV")

        case "4":
            options.add("-O")
        case "5":
            options.add("-A")
        case "6":
            if "-p-" in options:
                print("You have already chose all the ports")
            else:
                print("Enter your port range in the form 'X-Y' OR 'x,y,z,...'")
                ports = input()
                options.discard("-p")
                options.add(f"-p {ports}")

        case "7":
            options.add("-v")

        case "9":
            print(r"""
Welcome to advanced mode, If you're here you should know what the nmap 
options you want look like.
Type any extra options you want. *Make sure to add a space after each option
and to include the '-' prefix""")
            extra = input()
            options.add(extra)

def exportresult(scanner):
    results = []
    for host in scanner.all_hosts():
        host_entry = {
            "host": host,
            "state": scanner[host].state(),
            "protocols": []
        }
        for proto in scanner[host].all_protocols():
            proto_entry ={
                "protocol": proto,
                "ports" : []
            }
            ports = scanner[host][proto].keys()
            for port in ports:
                proto_entry["ports"].append({
                    "port" : port,
                    "state" : scanner[host][proto][port]['state']
                })
            host_entry["protocols"].append(proto_entry)
        results.append(host_entry)
    return results

#Start
os.system('clear') # Will only work on Unix/Linux
print(r"""+------------------------------------------+
|                                          |
|   ____                       ___         |
|  / ___|  ___ __ _ _ __  ____/ _ \ _ __   |
|  \___ \ / __/ _` | '_ \|_  / | | | '__|  |
|   ___) | (_| (_| | | | |/ /| |_| | |     |
|  |____/ \___\__,_|_| |_/___|\___/|_|     |
|                                          |
+------------------------------------------+""")
print(r"""
-------------------------------------------
-Most L33T scanner in the room
-Made by GeorgyB
-2026
-------------------------------------------
""")
#Target
print("Please enter target IP or hostname")
target = str(input())

#Nmap options
print("Choose your options: ")
print (r"""
 1) Quick Scan of the top 100 Ports 
 2) Full scan 
 3) Service Scan
 4) OS, Device and MAC Vendor scan
 5) Aggressive scan (WARNING, NOISY) 
 6) Set a port range from 0-10000
 7) Verbose Output
 9) Advanced Options ** 
 Choose your options and type 0 to confirm.""" )

options = set()
choice = input()

while choice != "0":
    pickoption(choice)
    print ("Currently selected Options: ",options)
    choice = input()


#Convert the options set into a  1 string
sep = " "
JoinedOptions = sep.join(options)

#Run the scan
print("Scanning ",target," with options: ",JoinedOptions)
scanner.scan(target, arguments=JoinedOptions)

#Present results
for host in scanner.all_hosts():
    print("+---------------------------------+")
    print("Host: ", host)
    print("State: ", scanner[host].state())
    for proto in scanner[host].all_protocols():
        print("Protocol: ", proto)
        ports = scanner[host][proto].keys()
        for port in ports:
            print ("Port: ", port, "State: ", scanner[host][proto][port]['state'])
    print("+---------------------------------+")

#Offer to Export results to json file
print("Would you like to export this to a JSON file? Y/N")
exChoice = input()
scandata = exportresult(scanner)

if exChoice == "Y" or exChoice == "y":
    with open('scanResult.json', 'w') as outfile:
        json.dump(scandata, outfile, indent=2)
        print("Results exported to scanResult.json. Have a nice day!")
elif exChoice == "N" or exChoice == "n":
    print("Have a nice day!")
    exit()
