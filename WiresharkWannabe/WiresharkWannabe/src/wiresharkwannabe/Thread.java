package wiresharkwannabe;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javafx.concurrent.Service;
import javafx.concurrent.Task;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
// to format data and get headers
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Rip;

import org.jnetpcap.packet.JRegistry;

// chapter 2.7
import org.jnetpcap.packet.PcapPacketHandler;

// chapter 3.1.2
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.packet.JPacket;

// For writing package data to file
import java.io.IOException;
import java.io.File;
import java.io.FileWriter;
import java.util.Date;
import java.text.DateFormat;
import java.text.SimpleDateFormat;

// For getting host IP address & MAC
import java.net.InetAddress;
import java.util.Enumeration;
import java.net.NetworkInterface;
import java.net.URL;

// For formatting mac & ip output
import org.jnetpcap.packet.format.FormatUtils;


/**
 *
 * @author Farida Abouish
 */
public class Thread extends Service{
    public static Ip4 ip = new Ip4();
    public static Ethernet eth = new Ethernet();
    public static Tcp tcp = new Tcp();
    public static Udp udp = new Udp();
   public static Arp arp = new Arp();
   public static Http http = new Http(); 
   
    public static List<PcapIf> alldevs = new ArrayList<PcapIf>();
    public static StringBuilder errbuf = new StringBuilder(); // For any error msgs  
    public static Pcap pcap;
   // public static PcapPacketHandler<String> jpacketHandler ;
    public static String src;
    public static String dest;
    public static String protocol;
    public static  Date header;
    public static int caplen;
    public static Info info;
    public static ArrayList <Info> packetInfo = new ArrayList();
    public static int counter = 0;
    static int r = Pcap.findAllDevs(alldevs, errbuf);
     //PcapIf  device = alldevs.get(0);
    
    public Thread (){
    int snaplen = 64 * 1024;           // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 10 * 1000;           // 10 seconds in millis  
        pcap= Pcap.openLive(WiresharkWannabe.device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return;
        }
    }
    
   PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

            public void nextPacket(PcapPacket packet, String user) {
              //  String hexdump = packet.toHexdump(packet.size(), false, false, true);
                //  System.out.println(hexdump);
                System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",
                        new Date(packet.getCaptureHeader().timestampInMillis()),
                        packet.getCaptureHeader().caplen(), // Length actually captured  
                        packet.getCaptureHeader().wirelen(), // Original length   
                        user // User supplied object  

                );
                if (packet.hasHeader(ip)) {
//                    if (FormatUtils.ip(ip.source()) != FormatUtils.ip(myinet)
//                            && FormatUtils.ip(ip.destination()) != FormatUtils.ip(myinet)) {
//                        System.out.println();
                     System.out.println("IP type:\t" + ip.typeEnum());
//                        System.out.println("IP src:\t-\t" + FormatUtils.ip(ip.source()));
//                  System.out.println("IP dst:\t-\t" + FormatUtils.ip(ip.destination()));
//                        readdata = true;
                        src = FormatUtils.ip(ip.source());
                        dest = FormatUtils.ip(ip.destination());
                        protocol = "IP";
                       
                //}
                }
                if (packet.hasHeader(eth))
//                        && readdata == true)
                        {
                    System.out.println("Ethernet type:\t" + eth.typeEnum());
                    System.out.println("Ethernet src:\t" + FormatUtils.mac(eth.source()));
                    System.out.println("Ethernet dst:\t" + FormatUtils.mac(eth.destination()));
                     src = FormatUtils.mac(eth.source());
                        dest = FormatUtils.mac(eth.destination());
                        protocol = "Ethernet";
                         
                }
                if(packet.hasHeader(http)){
                src = FormatUtils.ip(ip.source());
                dest = FormatUtils.ip(ip.destination());
                        protocol = "HTTP";
                }
               

           header = new Date(packet.getCaptureHeader().timestampInMillis());
           String time = String.valueOf(header);
           caplen = packet.getCaptureHeader().caplen();// Length actually captured  
           String leng = String.valueOf(caplen);
           String counterStr = String.valueOf(counter);
           info = new Info(counterStr,time,src,dest,protocol,leng,packet);
           WiresharkWannabe.information.add(info);
           counter++;
                        
            
            }

        };

    @Override
    protected Task createTask() {
       
    }

    
    
}