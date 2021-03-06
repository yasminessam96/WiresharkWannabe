/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wiresharkwannabe;

import com.jfoenix.controls.JFXButton;
import com.jfoenix.controls.JFXTextArea;
import com.jfoenix.controls.JFXTextField;
import java.io.File;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.layout.AnchorPane;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

/**
 * FXML Controller class
 *
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
    private TableColumn<Info, String> number;
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
    JFXButton capture = new JFXButton();
    @FXML
    JFXButton open = new JFXButton();
    @FXML
    JFXButton stop = new JFXButton();
    @FXML
    ComboBox comboBox = new ComboBox();
    @FXML
    private JFXTextArea details = new JFXTextArea();

    static StringBuilder errbuf = new StringBuilder();
    public static String deviceSelected;
    public static Capturing thread;
    public static List<PcapIf> alldevs = new ArrayList<PcapIf>();
    static int r = Pcap.findAllDevs(alldevs, errbuf);

    final FileChooser fileChooser = new FileChooser();

    ObservableList<String> devices = FXCollections.observableArrayList();

    OpenFile o;

    @FXML
    public void handleCaptureButtonAction(ActionEvent event) {
        int a = comboBox.getSelectionModel().getSelectedIndex();
        WiresharkWannabe.device = alldevs.get(a);
        thread = new Capturing();
        thread.start();
    }

    @FXML
    public void handleStopButtonAction(ActionEvent event) {

        thread.cancel();
      
    }

    @FXML
    public void handleSelection() {
        Info selectedPacket = output.getSelectionModel().getSelectedItem();
        details.setText(selectedPacket.getPacket().toString());

    }

    @FXML
    public void handleOpenButtonAction(ActionEvent event) {
        WiresharkWannabe.information.clear();

        Stage primaryStage = new Stage();

        File file = fileChooser.showOpenDialog(primaryStage);

        if (file == null) {
            System.out.println("error");
        } else {
         
            o = new OpenFile(file.getAbsoluteFile().getAbsolutePath());
            o.start();
        }

    }

    @Override
    public void initialize(URL url, ResourceBundle rb) {
      

        number.setCellValueFactory(cellData -> cellData.getValue().getNumber());
        time.setCellValueFactory(cellData -> cellData.getValue().gettime());
        source.setCellValueFactory(cellData -> cellData.getValue().getipSource());
        destination.setCellValueFactory(cellData -> cellData.getValue().getipDestination());
        protocol.setCellValueFactory(cellData -> cellData.getValue().getprotocol());
        length.setCellValueFactory(cellData -> cellData.getValue().getlength());

        FilteredList<Info> filteredData = new FilteredList<>(WiresharkWannabe.information, p -> true);
        filterSearch.textProperty().addListener((observable, oldValue, newValue) -> {
            filteredData.setPredicate(data -> {
                // If filter text is empty, display all entries.
                if (newValue == null || newValue.isEmpty()) {
                    return true;
                }

                // Compare filter text.
                String lowerCaseFilter = newValue.toLowerCase();

                if (data.getprotocol().getValue().toLowerCase().contains(lowerCaseFilter)) {
                    return true; // match
                }

                return false; // no match
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
