package wiresharkwannabe;

import java.util.ArrayList;
import java.util.List;
import javafx.concurrent.Service;
import javafx.concurrent.Task;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.network.Arp;

// chapter 2.7
import org.jnetpcap.packet.PcapPacketHandler;

// chapter 3.1.2
import org.jnetpcap.protocol.network.Ip4;
import java.util.Date;
import org.jnetpcap.PcapDumper;

// For formatting mac & ip output
import org.jnetpcap.packet.format.FormatUtils;

/**
 *
 *
 */
public class Capturing extends Service {

    public static Ip4 ip = new Ip4();
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
    public static int fileNum = 1;
     String ofile;
    PcapDumper dumper;

    public Capturing() {
        int snaplen = 64 * 1024;           // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 10 * 1000;           // 10 seconds in millis  
        pcap = Pcap.openLive(WiresharkWannabe.device.getName(), snaplen, flags, timeout, errbuf);

        ofile = "file" + fileNum + ".pcap";
        fileNum++;
        dumper = pcap.dumpOpen(ofile);
    }

    PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

        public void nextPacket(PcapPacket packet, String user) {
            dumper.dump(packet.getCaptureHeader(), packet);
          
            if (packet.hasHeader(http)) {
                src = FormatUtils.ip(ip.source());
                dest = FormatUtils.ip(ip.destination());
                protocol = "HTTP";

            } 
           else if (packet.hasHeader(ip)) {


                src = FormatUtils.ip(ip.source());
                dest = FormatUtils.ip(ip.destination());
                protocol = ip.typeEnum().toString();


            } 
            
         else   if (packet.hasHeader(arp)) {

                src = FormatUtils.ip(ip.source());
                dest = FormatUtils.ip(ip.destination());
                protocol = "ARP";
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
