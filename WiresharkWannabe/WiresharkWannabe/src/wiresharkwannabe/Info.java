/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wiresharkwannabe;

import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import org.jnetpcap.packet.PcapPacket;

public class Info {

    private StringProperty Number;
    private StringProperty time;
    private StringProperty ipSource;
    private StringProperty ipDestination;
    private StringProperty protocol;
    private StringProperty length;
    private StringProperty information;
    private PcapPacket packet;

    public Info() {
        this(null, null, null, null, null, null, null);
    }

    public Info(String n, String t, String ips, String ipd, String p, String l, PcapPacket pack) {

        this.Number = new SimpleStringProperty(n);
        this.time = new SimpleStringProperty(t);
        this.ipSource = new SimpleStringProperty(ips);
        this.ipDestination = new SimpleStringProperty(ipd);
        this.protocol = new SimpleStringProperty(p);
        this.length = new SimpleStringProperty(l);
        this.packet = pack;

    }

    public StringProperty getNumber() {
        return Number;
    }

    public StringProperty gettime() {
        return time;
    }

    public StringProperty getipSource() {
        return ipSource;
    }

    public StringProperty getipDestination() {
        return ipDestination;
    }

    public StringProperty getprotocol() {
        return protocol;
    }

    public StringProperty getlength() {
        return length;
    }

    public PcapPacket getPacket() {
        return packet;
    }

}
