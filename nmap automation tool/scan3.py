import nmap

scanner = nmap.PortScanner()
print("Welcome to the nmap automation tool")
print("<*******************************>")

ipaddr = input("Enter the IP address you want to scan: ")
print("The IP you entered is:", ipaddr)

resp = input("""\nPlease enter the type of scan you want to run:
                1) SYN ACK Scan
                2) UDP Scan
                3) Comprehensive Scan \n""")
print("You have selected option:", resp)

resp_dict = {'1': ['-v -sS', 'tcp'], '2': ['-v -sU', 'udp'], '3': ['-v -sS -sV -sC -A -O', 'tcp']}

if resp not in resp_dict.keys():
    print("Enter a valid option")
else:
    print("nmap version:", scanner.nmap_version())
    scanner.scan(ipaddr, "1-1024", resp_dict[resp][0])  # Port range to scan, the last part is the scan type
    print(scanner.scaninfo())
    if scanner[ipaddr].state() == 'up':
        print("Scanner Status:", scanner[ipaddr].state())
        print("Protocols:", scanner[ipaddr].all_protocols())
        protocol = resp_dict[resp][1]
        if protocol in scanner[ipaddr]:
            print("Open Ports:", scanner[ipaddr][protocol].keys())
        else:
            print("No open ports found.")
    else:
        print("Scanner Status:", scanner[ipaddr].state())
        print("The host seems to be down.")
