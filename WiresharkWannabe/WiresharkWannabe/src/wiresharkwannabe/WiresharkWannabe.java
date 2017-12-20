/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wiresharkwannabe;

import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import org.jnetpcap.Pcap;

// chapter 2.6
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;

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

import java.util.Arrays;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.layout.Pane;

/**
 *
 * @author Yasmin
 */
public class WiresharkWannabe extends Application  {

    

    public static ObservableList<Info> information = FXCollections.observableArrayList();
    public static List<PcapIf> alldevs = new ArrayList<PcapIf>();
    public static StringBuilder errbuf = new StringBuilder(); // For any error msgs  
    public static Pcap pcap;
  
    public static ArrayList <Info> packetInfo = new ArrayList();
   

    static int r = Pcap.findAllDevs(alldevs, errbuf);
     static PcapIf device;
     @Override
    public void start(Stage stage) throws IOException{
        
        FXMLLoader loader = new FXMLLoader (getClass().getResource("MainPage2.fxml"));
       Parent root =loader.load();
      MainPage2Controller myController = loader.getController();
        Scene scene = new Scene(root);
        
   
        stage.setScene(scene);
       stage.resizableProperty().setValue(Boolean.FALSE);
stage.show();
myController.fillComboBox();  
        
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf
                    .toString());
            return;
        }

        System.out.println("Network devices found:");

        int i = 0;
        for (PcapIf device : alldevs) {
            String description
                    = (device.getDescription() != null) ? device.getDescription()
                            : "No description available";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }
     


    }

   


/**
 * @param args the command line arguments
 */
public static void main(String[] args) throws Exception {
        launch(args);
       

    }

    

   
}
