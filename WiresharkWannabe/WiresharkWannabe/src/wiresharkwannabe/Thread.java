package wiresharkwannabe;

import java.util.ArrayList;
import java.util.List;
import javafx.concurrent.Service;
import javafx.concurrent.Task;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.network.Arp;

// chapter 2.7
import org.jnetpcap.packet.PcapPacketHandler;

// chapter 3.1.2
import org.jnetpcap.protocol.network.Ip4;
import java.util.Date;

// For formatting mac & ip output
import org.jnetpcap.packet.format.FormatUtils;

/**
 *
 *
 */
public class Thread extends Service {

    public static Ip4 ip = new Ip4();
    public static Ethernet eth = new Ethernet();
    public static Tcp tcp = new Tcp();
    public static Udp udp = new Udp();
    public static Arp arp = new Arp();
    public static Http http = new Http();

    public static List<PcapIf> alldevs = new ArrayList<PcapIf>();
    public static StringBuilder errbuf = new StringBuilder(); // For any error msgs  
    public static Pcap pcap;

    public static String src;
    public static String dest;
    public static String protocol;
    public static Date header;
    public static int caplen;
    public static Info info;
    public static ArrayList<Info> packetInfo = new ArrayList();
    public static int counter = 0;
    static int r = Pcap.findAllDevs(alldevs, errbuf);

    public Thread() {
        int snaplen = 64 * 1024;           // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 10 * 1000;           // 10 seconds in millis  
        pcap = Pcap.openLive(WiresharkWannabe.device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return;
        }
    }

    PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

        public void nextPacket(PcapPacket packet, String user) {

            System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",
                    new Date(packet.getCaptureHeader().timestampInMillis()),
                    packet.getCaptureHeader().caplen(), // Length actually captured  
                    packet.getCaptureHeader().wirelen(), // Original length   
                    user // User supplied object  

            );
            if (packet.hasHeader(ip)) {

                src = FormatUtils.ip(ip.source());
                dest = FormatUtils.ip(ip.destination());
                protocol = "IP";

                //}
            }
            if (packet.hasHeader(eth)) {
                src = FormatUtils.mac(eth.source());
                dest = FormatUtils.mac(eth.destination());
                protocol = "Ethernet";

            }
            if (packet.hasHeader(http)) {
                src = FormatUtils.ip(ip.source());
                dest = FormatUtils.ip(ip.destination());
                protocol = "HTTP";
            }

            if (packet.hasHeader(arp)) {
                src = FormatUtils.ip(ip.source());
                dest = FormatUtils.ip(ip.destination());
                protocol = "ARP";
            }
            if (packet.hasHeader(tcp)) {
                System.out.println("TCP src port:\t" + tcp.source());
                System.out.println("TCP dst port:\t" + tcp.destination());
                src = String.valueOf(tcp.source());
                dest = String.valueOf(tcp.destination());
                protocol = "TCP";
            } else if (packet.hasHeader(udp)) {
                System.out.println("UDP src port:\t" + udp.source());
                System.out.println("UDP dst port:\t" + udp.destination());
                src = String.valueOf(udp.source());
                dest = String.valueOf(udp.destination());
                protocol = "UDP";

            }
            header = new Date(packet.getCaptureHeader().timestampInMillis());
            String time = String.valueOf(header);
            caplen = packet.getCaptureHeader().caplen();// Length actually captured  
            String leng = String.valueOf(caplen);
            String counterStr = String.valueOf(counter);
            info = new Info(counterStr, time, src, dest, protocol, leng, packet);
            WiresharkWannabe.information.add(info);
            counter++;

        }

    };

    @Override
    protected Task createTask() {

        return new Task() {
            @Override
            protected Object call() throws Exception {
                while (true) {
                    if (isCancelled()) {
                        break;
                    }

                    pcap.loop(1, jpacketHandler, "");
                }
                return null;
            }
        };
    }

}
