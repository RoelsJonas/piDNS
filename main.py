from scapy.all import *

def main():
    running = True

    #stel asynchrone sniffer in op port 53 (standaard poort voor dns queries)
    t = AsyncSniffer(filter = "port 53")

    #maak een lege resulst lijst aan
    results = []

    #zolang de dns server runt blijf loopen
    while(running):

        # start de sniffer
        t.start()

        #loop daar alle gecapturde packets
        for packet in results:
            print(packet)

            # als packet een dns request is kijk of overeenkomstig ip in geheugen zit

                # als ip in geheugen zit kijk of recursie vereist is

                    #geen recursie vereist ==> stuur gekend ip terug

                    # wel recursie vereist ==> vergelijk met TLD server voor dat domein
                    #stuur waarde van TLD terug en pas eventueel gekend ip aan

                # ip niet in geheugen ==> zoek naar TLD server voor domein
                # voeg waarde toe aan TLD server en return naar de client

        #stop de sniffer en update de results
        results = t.stop()



# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()

