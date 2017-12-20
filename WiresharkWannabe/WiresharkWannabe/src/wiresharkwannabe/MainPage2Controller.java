/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wiresharkwannabe;

//import com.jfoenix.controls.JFXButton;
//import com.jfoenix.controls.JFXTextArea;
//import com.jfoenix.controls.JFXTextField;
//import java.net.URL;
//import java.util.ArrayList;
//import java.util.List;
//import java.util.ResourceBundle;
//import javafx.collections.FXCollections;
//import javafx.collections.ObservableList;
//import javafx.collections.transformation.FilteredList;
//import javafx.event.ActionEvent;
//import javafx.fxml.FXML;
//import javafx.fxml.Initializable;
//import javafx.scene.control.ComboBox;
//import javafx.scene.control.TableColumn;
//import javafx.scene.control.TableView;
//import javafx.scene.input.MouseEvent;
//import javafx.scene.layout.AnchorPane;
//import javafx.scene.text.Text;
//import org.jnetpcap.Pcap;
//import org.jnetpcap.PcapIf;

import com.jfoenix.controls.JFXButton;
import com.jfoenix.controls.JFXComboBox;
import com.jfoenix.controls.JFXTextArea;
import com.jfoenix.controls.JFXTextField;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.Pane;
import javafx.scene.text.Text;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;


/**
 * FXML Controller class
 *
 * @author Farida Abouish
 */
public class MainPage2Controller implements Initializable {
    @FXML
    private AnchorPane pane;
    @FXML
    private Text filter;
    @FXML
    private TableView<?> output;
    @FXML
    private TableColumn<?, ?> number;
    @FXML
    private TableColumn<?, ?> time;
    @FXML
    private TableColumn<?, ?> source;
    @FXML
    private TableColumn<?, ?> destination;
    @FXML
    private TableColumn<?, ?> protocol;
    @FXML
    private TableColumn<?, ?> length;
    @FXML
    private TableColumn<?, ?> information;
    @FXML
    private JFXTextField filterSearch;
    @FXML
//    private JFXButton capture;
//    @FXML
//    private JFXButton stop;
//    @FXML
//    private JFXTextArea details;
//    @FXML
//    private ComboBox<?> comboBox;
    
    JFXButton capture = new JFXButton();
      @FXML
JFXButton stop = new JFXButton();
     @FXML
      ComboBox comboBox = new ComboBox();
     @FXML
   private JFXTextArea details = new JFXTextArea();
    
     
     static StringBuilder errbuf = new StringBuilder();
   public static String deviceSelected;
     public static java.lang.Thread thread;
      public static List<PcapIf> alldevs = new ArrayList<PcapIf>();
     static int r = Pcap.findAllDevs(alldevs, errbuf); 
     
      ObservableList<String> devices = FXCollections.observableArrayList();

  
      @FXML
    private void handleSelection(MouseEvent event) {
        Info selectedPacket = output.getSelectionModel().getSelectedItem();
      details.setText(selectedPacket.getPacket().toString());
    }

    @FXML
    private void handleCaptureButtonAction(ActionEvent event) {
        int a = comboBox.getSelectionModel().getSelectedIndex();
         WiresharkWannabe.device = alldevs.get(a);
       thread = new java.lang.Thread();
       thread.start();
    }

    @FXML
    private void handleStopButtonAction(ActionEvent event) {
           //     thread.cancel();

    }
      
      
      
    @Override
    public void initialize(URL url, ResourceBundle rb) {
               // fillComboBox();
      
        number.setCellValueFactory(cellData -> cellData.getValue().getNumber());
        time.setCellValueFactory(cellData -> cellData.getValue().gettime());
        source.setCellValueFactory(cellData -> cellData.getValue().getipSource());
        destination.setCellValueFactory(cellData -> cellData.getValue().getipDestination());
        protocol.setCellValueFactory(cellData -> cellData.getValue().getprotocol());
        length.setCellValueFactory(cellData -> cellData.getValue().getlength());
        
         FilteredList<Info> filteredData = new FilteredList<>(WiresharkWannabe.information, p -> true);
           filterSearch.textProperty().addListener((observable, oldValue, newValue) -> {
            filteredData.setPredicate(data -> {
                // If filter text is empty, display all persons.
                if (newValue == null || newValue.isEmpty()) {
                    return true;
                }

                // Compare first name and last name of every person with filter text.
                String lowerCaseFilter = newValue.toLowerCase();

                if (data.getprotocol().getValue().toLowerCase().contains(lowerCaseFilter)) {
                    return true; // Filter matches first name.
                } 
                return false; // Does not match.
            });
        });
           output.setItems(filteredData);
    }    
    
    
    public void fillComboBox() {
      
       for (PcapIf device : alldevs) {  
            devices.add(device.getDescription());
        }  
        comboBox.setItems(devices);

    }

    
    
}
