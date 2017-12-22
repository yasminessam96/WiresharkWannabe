/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wiresharkwannabe;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import javafx.concurrent.Service;
import javafx.concurrent.Task;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 *
 * @author Yasmin
 */
public class OpenFile extends Service {

    public static String src;
    public static String dest;
    public static String prot;
    public static Date header;
    public static int caplen;
    public static Info info;
    public static ArrayList<Info> packetInfo = new ArrayList();
    public static int counter = 0;
    final StringBuilder errbuf = new StringBuilder();
    public static Ip4 ip = new Ip4();
    public static Ethernet eth = new Ethernet();
    public static Tcp tcp = new Tcp();
    public static Udp udp = new Udp();
    public static Arp arp = new Arp();
    public static Http http = new Http();
    PcapPacketHandler<String> jpacketHandler;
    String fname;
    Pcap pcap2;

    public OpenFile(String fname) {
        this.fname = fname;
        pcap2 = Pcap.openOffline(this.fname, errbuf);
        System.out.print(errbuf);
        System.out.print(fname);
        this.jpacketHandler = new PcapPacketHandler<String>() {

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
                    prot = "IP";
                    System.out.println(prot);
                    //}
                }
                if (packet.hasHeader(eth)) {
                    src = FormatUtils.mac(eth.source());
                    dest = FormatUtils.mac(eth.destination());
                    prot = "Ethernet";
                    System.out.println(prot);
                }
                if (packet.hasHeader(http)) {
                    src = FormatUtils.ip(ip.source());
                    dest = FormatUtils.ip(ip.destination());
                    prot = "HTTP";
                    System.out.println(prot);
                }

                if (packet.hasHeader(arp)) {
                    src = FormatUtils.ip(ip.source());
                    dest = FormatUtils.ip(ip.destination());
                    prot = "ARP";
                }
                if (packet.hasHeader(tcp)) {
                    System.out.println("TCP src port:\t" + tcp.source());
                    System.out.println("TCP dst port:\t" + tcp.destination());
                    src = String.valueOf(tcp.source());
                    dest = String.valueOf(tcp.destination());
                    prot = "TCP";
                } else if (packet.hasHeader(udp)) {
                    System.out.println("UDP src port:\t" + udp.source());
                    System.out.println("UDP dst port:\t" + udp.destination());
                    src = String.valueOf(udp.source());
                    dest = String.valueOf(udp.destination());
                    prot = "UDP";

                }
                header = new Date(packet.getCaptureHeader().timestampInMillis());
                String time = String.valueOf(header);
                caplen = packet.getCaptureHeader().caplen();// Length actually captured  
                String leng = String.valueOf(caplen);
                String counterStr = String.valueOf(counter);
                info = new Info(counterStr, time, src, dest, prot, leng, packet);
                WiresharkWannabe.information.add(info);
                System.out.println(prot);
                System.out.println(counter);
                counter++;

            }

        };

    }

    @Override
    protected Task createTask() {

        return new Task() {
            @Override
            protected Object call() throws Exception {
                while (true) {
                    if (isCancelled()) {
                        break;
                    }

                    pcap2.loop(-1, jpacketHandler, "lolzz");
                }
                return null;
            }
        };
    }
}
