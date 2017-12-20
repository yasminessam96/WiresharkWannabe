/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wiresharkwannabe;

import com.jfoenix.controls.JFXButton;
import com.jfoenix.controls.JFXTextArea;
import com.jfoenix.controls.JFXTextField;
import java.net.URL;
import java.util.ResourceBundle;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;
import javafx.scene.text.Text;

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
    private JFXButton capture;
    @FXML
    private JFXButton stop;
    @FXML
    private JFXTextArea details;
    @FXML
    private ComboBox<?> comboBox;

  
    @Override
    public void initialize(URL url, ResourceBundle rb) {
        // TODO
    }    

    @FXML
    private void handleSelection(MouseEvent event) {
    }

    @FXML
    private void handleCaptureButtonAction(ActionEvent event) {
    }

    @FXML
    private void handleStopButtonAction(ActionEvent event) {
    }
    
}
