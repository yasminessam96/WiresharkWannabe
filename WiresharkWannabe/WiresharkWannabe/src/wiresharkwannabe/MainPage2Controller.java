/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wiresharkwannabe;
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
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.Pane;
import javafx.scene.text.Text;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;


/**
 * FXML Controller class
 *
 
 */
public class MainPage2Controller implements Initializable {
    @FXML
    private AnchorPane pane;
   
    @FXML
    private Text filter;
     @FXML
    private JFXTextField filterSearch;
    @FXML
    private TableView<Info> output;
    @FXML
    private TableColumn<Info , String> number;
    @FXML
    private TableColumn<Info, String> time;
    @FXML
    private TableColumn<Info, String> source;
    @FXML
    private TableColumn<Info, String> destination;
    @FXML
    private TableColumn<Info, String> protocol;
    @FXML
    private TableColumn<Info, String> length;
    @FXML
    private TableColumn<Info, String> information;
     @FXML
JFXButton capture = new JFXButton();
      @FXML
JFXButton stop = new JFXButton();
     @FXML
      ComboBox comboBox = new ComboBox();
     @FXML
   private JFXTextArea details = new JFXTextArea();
     
     static StringBuilder errbuf = new StringBuilder();
   public static String deviceSelected;
     public static Thread thread;
      public static List<PcapIf> alldevs = new ArrayList<PcapIf>();
     static int r = Pcap.findAllDevs(alldevs, errbuf); 
     
      ObservableList<String> devices = FXCollections.observableArrayList();
     
     
     @FXML
      public void handleCaptureButtonAction(ActionEvent event) {
          int a = comboBox.getSelectionModel().getSelectedIndex();
         WiresharkWannabe.device = alldevs.get(a);
       thread = new Thread();
       thread.start();
       }
        @FXML
      public void handleStopButtonAction(ActionEvent event) {
         thread.cancel();
        
       }
      
       @FXML
      public void handleSelection(){
      Info selectedPacket = output.getSelectionModel().getSelectedItem();
      details.setText(selectedPacket.getPacket().toString());
      
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