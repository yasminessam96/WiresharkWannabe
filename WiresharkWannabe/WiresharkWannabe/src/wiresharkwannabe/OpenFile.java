/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wiresharkwannabe;

import java.util.ArrayList;
import java.util.Date;
import javafx.concurrent.Service;
import javafx.concurrent.Task;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;


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

                 if (packet.hasHeader(http)) {
                src = FormatUtils.ip(ip.source());
                dest = FormatUtils.ip(ip.destination());
                prot= "HTTP";

            } else if (packet.hasHeader(ip)) {

                src = FormatUtils.ip(ip.source());
                dest = FormatUtils.ip(ip.destination());
                prot = ip.typeEnum().toString();

            } 
            else if (packet.hasHeader(arp)) {
                src = FormatUtils.ip(ip.source());
                dest = FormatUtils.ip(ip.destination());
                prot = "ARP";
            }

               
                header = new Date(packet.getCaptureHeader().timestampInMillis());
                String time = String.valueOf(header);
                caplen = packet.getCaptureHeader().caplen();// Length actually captured  
                String leng = String.valueOf(caplen);
                String counterStr = String.valueOf(counter);
                info = new Info(counterStr, time, src, dest, prot, leng, packet);
                WiresharkWannabe.information.add(info);
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

                    pcap2.loop(-1, jpacketHandler, "");
                }
                return null;
            }
        };
    }
}
