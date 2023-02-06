package com.against.oascan;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.RadioButton;
import javafx.scene.control.TextField;
import javafx.stage.Stage;

public class ProxyController {
    private MainController mainController;

    @FXML
    private RadioButton disableRadioButton;

    @FXML
    private RadioButton enableRadioButton;

    @FXML
    private Button cancelButton;

    @FXML
    private Button saveButton;

    @FXML
    private ChoiceBox<String> proxyTypeChoiceBox;

    @FXML
    private TextField proxyHostField;

    @FXML
    private TextField proxyPortField;

    public void setMainController(MainController mainController) {
        this.mainController = mainController;
    }

    @FXML
    void initialize() {
        proxyTypeChoiceBox.getItems().addAll("HTTP", "SOCKS");
        proxyTypeChoiceBox.setValue("HTTP");
    }

    @FXML
    public void setpoxyField(String host, Integer port, boolean proxyIsEnable){
        this.proxyHostField.setText(host);
        this.proxyPortField.setText(String.valueOf(port));
        if (proxyIsEnable) {
            enableRadioButton.setSelected(true);
        }else {
            disableRadioButton.setSelected(true);
        }
    }

    @FXML
    public void saveButtonAction(ActionEvent event) {
        if (enableRadioButton.isSelected()) {
            Stage stage = (Stage) saveButton.getScene().getWindow();
            stage.close();
            mainController.setGlobalProxy(proxyHostField.getText(), Integer.parseInt(proxyPortField.getText()), true);
        } else {
            Stage stage = (Stage) saveButton.getScene().getWindow();
            stage.close();
            mainController.setGlobalProxy(proxyHostField.getText(), Integer.parseInt(proxyPortField.getText()), false);
        }
    }

    @FXML
    public void cancelButtonAction(ActionEvent event) {
        Stage stage = (Stage) cancelButton.getScene().getWindow();
        stage.close();
    }
}
