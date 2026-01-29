#!/usr/bin/python3

#to do
#Prettier Output, Start screen (clear), progress bar?, output to a file

import nmap

scanner = nmap.PortScanner()

#Target
print("Please enter target IP or hostname")
target = str(input())

#Nmap options
print("Choose your options: ")
print (" 1) sS - TCP SYN scan \n 2) sV - Probe open ports \n 3) O - OS detection \n 4) A - Aggressive scan \n 5) p - Port range from 0-10000 \n Choose your options and type 0 to confirm.\n")

options = set()
choice = input()
while choice != "0":

    if choice == "1":
        options.add("-sS")

    elif choice == "2":
        options.add("-sV")

    elif choice == "3":
        options.add("-O")

    elif choice == "4":
        options.add("-A")

    elif choice == "5":
        print("Enter your port range in the form 'X-Y'")
        ports = input()
        options.discard("-p")
        options.add(f"-p {ports}")
    print (options)
    choice = input()

#Convert the options set into a  1 string
sep = " "
JoinedOptions = sep.join(options)

#Run a basic scan
print("Scanning ",target," with options: ",JoinedOptions)
scanner.scan(target, arguments=JoinedOptions)

#Present results
for host in scanner.all_hosts():
    print("Host: ", host)
    print("State: ", scanner[host].state())
    for proto in scanner[host].all_protocols():
        print("Protocol: ", proto)
        ports = scanner[host][proto].keys()
        for port in ports:
            print ("Port: ", port, "State: ", scanner[host][proto][port]['state'])

