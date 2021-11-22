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
            #check of het een binnenkomende DNS qeury is
            if packet[IP].dst == hostIP and packet[DNS].qr == 0:
                print("generating response", packet[IP].src)

                #bouw een layer 3 packet met als bestemming het IP vanwaar de query komt
                networkLayer = IP(dst=packet[IP].src)
                #bouw een UDP packet met als destination port de port vanwaar de DNS query verzonden is
                transportLayer = UDP(dport=packet[UDP].sport,sport=53)

                #zoek het overeenkomstig IP met de domain name vanuit de query
                siteIP = getSiteIP(packet[DNS.qd.qname])


                #bouw een application layer packet
                applicationLayer = DNS(id=packet[DNS].id, #het transaction id van de DNS query
                                       aa=1, #zegt of het een authorative answer is of niet
                                       qr=1, #zegt dat het een antwoord is en geen query
                                       rd=packet[DNS].rd, #zegt of recursion desired is
                                       qdcount=packet[DNS].qdcount, #aantal queries, zelfde als aantal queries die ontvangen zijn
                                       qd=packet[DNS].qd, #de query
                                       ancount=1, #het aantal antwoorden dat we versturen
                                       an=DNSRR(rrname=packet[DNS].qd.qname, #de domain name waarvoor we antwoorden
                                                type='A', #het type antwoord, A voor een standaard host name query
                                                ttl=1, #time to live, hoe lang de client er mag van uit gaan dat het IP niet verandert
                                                rdata=siteIP)) #het ip dat overeen komt met de host name

                #bouw het volledige packet
                DNSAnswer = networkLayer/transportLayer/applicationLayer
                #verstuur het packet (level 3)
                dnsResponse = sr1(DNSAnswer, timeout=1)

        #stop de sniffer en update de results
        results = t.results



# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()

