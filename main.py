from scapy.all import *

nameDirectory = []
IPDirectory = []
DNSBACKUP = '10.99.6.1'

def getSiteIP(siteName):
    global nameDirectory
    global IPDirectory
    siteIP = ""
    found = False

    for i in range(len(nameDirectory)):
        if nameDirectory[i] == siteName:
            siteIP = IPDirectory[i]
            found = True

    if not(found):
        networkLayer = IP(dst=DNSBACKUP)
        transportLayer = UDP(dport=53, sport=56980)
        applicationLayer = DNS(id=0x6000, rd=1, qd=DNSQR(qname=siteName, qtype= 'A'))

        DNSQuery = networkLayer/transportLayer/applicationLayer

        DNSrespone = sr1(DNSQuery)

        siteIP = DNSrespone[DNS].an.rdata

        nameDirectory.append(siteName)
        IPDirectory.append(siteIP)

    return(siteIP)



def main():
    running = True

    #stel asynchrone sniffer in op port 53 (standaard poort voor dns querie
    t = AsyncSniffer(count=1, filter = "port 53")
    #maak een lege resulst lijst aan
    results = []
    count = 0
    hostIP = get_if_addr(conf.iface)
    #zolang de dns server runt blijf loopen
    while(running):
        count += 1
        # start de sniffer
        t.start()
        t.join()

        #loop daar alle gecapturde packets
        for packet in results:
            if packet[IP].dst == hostIP and packet[DNS].qr == 0:
                print("generating response", packet[IP].src)
                siteName = packet[DNS].qd.qname
                networkLayer = IP(dst=packet[IP].src)
                transportLayer = UDP(dport=packet[UDP].sport, sport=53)
                siteIP = getSiteIP(siteName)
                applicationLayer = DNS(id=packet[DNS].id, aa=1, qr=1, rd=packet[DNS].rd, qdcount=packet[DNS].qdcount, qd=packet[DNS].qd, ancount=1, an=DNSRR(rrname=packet[DNS].qd.qname, type='A', ttl=1, rdata=siteIP))

                DNSAnswer = networkLayer/transportLayer/applicationLayer
                dnsResponse = sr1(DNSAnswer, timeout=1)



            # als packet een dns request is kijk of overeenkomstig ip in geheugen zit

                # als ip in geheugen zit kijk of recursie vereist is

                    #geen recursie vereist ==> stuur gekend ip terug

                    # wel recursie vereist ==> vergelijk met TLD server voor dat domein
                    #stuur waarde van TLD terug en pas eventueel gekend ip aan

                # ip niet in geheugen ==> zoek naar TLD server voor domein
                # voeg waarde toe aan TLD server en return naar de client

        #stop de sniffer en update de results
        results = t.results



# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()

