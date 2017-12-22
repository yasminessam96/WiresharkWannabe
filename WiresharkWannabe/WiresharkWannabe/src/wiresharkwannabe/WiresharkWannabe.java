/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wiresharkwannabe;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.stage.Stage;
import java.util.ArrayList;

import org.jnetpcap.PcapIf;

import org.jnetpcap.Pcap;

// chapter 2.6
// For writing package data to file
import java.io.IOException;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;

/**
 *
 *
 */
public class WiresharkWannabe extends Application {

    public static ObservableList<Info> information = FXCollections.observableArrayList();
    // public static List<PcapIf> alldevs = new ArrayList<PcapIf>();
    public static ObservableList<PcapIf> alldevs = FXCollections.observableArrayList();
    public static StringBuilder errbuf = new StringBuilder(); // For any error msgs  
    public static Pcap pcap;

    public static ArrayList<Info> packetInfo = new ArrayList();

    static int r = Pcap.findAllDevs(alldevs, errbuf);
    static PcapIf device;

    @Override
    public void start(Stage stage) throws IOException {

        FXMLLoader loader = new FXMLLoader(getClass().getResource("MainPage2.fxml"));
        Parent root = loader.load();
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
