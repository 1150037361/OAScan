package com.against.oascan;

import com.against.oascan.poc.SeeyonPoc;
import com.against.oascan.poc.TongdaPoc;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.stage.Stage;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;

public class MainController {
    private ProxyController proxyController;
    private String proxyHost = null;
    private Integer proxyPort = null;
    private boolean proxyIsEnable = false;
    private Proxy proxy = null;

    @FXML
    private Label proxStatusLabel;

    @FXML
    private ChoiceBox<String> seeyonPocTypeChoiceBox;

    @FXML
    private ChoiceBox<String> tdPocTypeChoiceBox;

    @FXML
    private TextField seeyonUrlTextField;

    @FXML
    private TextField tdUrlTextField;

    @FXML
    private TextArea seeyonScanInfoTextArea;

    @FXML
    private TextArea tdScanInfoTextArea;


    /**
     * 初始化ChoiceBox
     */
    @FXML
    public void initialize() {
        //初始化致远OA的漏洞类型
        seeyonPocTypeChoiceBox.getItems().addAll("敏感信息泄露", "SQL注入", "Session泄露", "webmail任意文件下载", "htmlofficeservlet任意文件写入", "ajax文件上传", "ALL");
        seeyonPocTypeChoiceBox.setValue("ALL");

        //初始化通达OA的漏洞类型
        tdPocTypeChoiceBox.getItems().addAll( "文件上传GetShell", "测试方法");
        tdPocTypeChoiceBox.setValue("文件上传GetShell");
    }

    /**
     * 获取全局的代理配置
     *
     * @param proxyHost
     * @param proxyport
     */
    public void setGlobalProxy(String proxyHost, int proxyport, boolean isEnable) {
        this.proxyHost = proxyHost;
        this.proxyPort = proxyport;
        this.proxyIsEnable = isEnable;
        if (isEnable) {
            this.proxStatusLabel.setText("代理生效中：" + proxyHost + ":" + proxyport);
            this.proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(this.proxyHost, this.proxyPort));

        } else {
            this.proxy = null;
            this.proxStatusLabel.setText("代理未设置");
        }
    }

    /**
     * 设置代理界面
     *
     * @param event
     * @throws IOException
     */
    public void setProxyMenuItemAction(ActionEvent event) throws IOException {
        FXMLLoader proxyFxml = new FXMLLoader(getClass().getResource("proxy-view.fxml"));
        Parent root = proxyFxml.load();
        Stage proxyStage = new Stage();

        //将主界面的controller传给子界面
        proxyController = proxyFxml.getController();
        proxyController.setMainController(this);
        if (proxyHost != null) {
            proxyController.setpoxyField(proxyHost, proxyPort, proxyIsEnable);
        }

        proxyStage.setTitle("代理设置");
        proxyStage.getIcons().add(new Image("img/a.png"));
        proxyStage.setScene(new Scene(root));
        proxyStage.show();
    }

    public void helpMenuItemAction(ActionEvent event) throws IOException {
        FXMLLoader proxyFxml = new FXMLLoader(getClass().getResource("help-view.fxml"));
        Parent root = proxyFxml.load();
        Stage proxyStage = new Stage();


        proxyStage.setTitle("帮助");
        proxyStage.getIcons().add(new Image("img/a.png"));
        proxyStage.setScene(new Scene(root));
        proxyStage.show();
    }


    /**
     * 扫描致远OA漏洞方法
     */
    @FXML
    public void scanSeeyonVul() {
        if (seeyonUrlTextField.getText().isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.WARNING);
            alert.setTitle("错误");
            alert.setContentText("目标地址为空或者输入错误！！！！！");
            alert.setHeaderText("目标地址错误");
            alert.showAndWait();
        } else {
            new Thread(() -> {
                SeeyonPoc seeyonPoc = new SeeyonPoc(this.proxy, seeyonUrlTextField.getText(), this);
                switch (seeyonPocTypeChoiceBox.getValue()) {
                    case "ALL":
                        seeyonPoc.allVulScan();
                        break;
                    case "ajax文件上传":
                        seeyonPoc.ajaxVulScan();
                        break;
                    case "webmail任意文件下载":
                        seeyonPoc.webMailVulScan();
                        break;
                    case "Session泄露":
                        seeyonPoc.sessionVulScan();
                        break;
                    case "敏感信息泄露":
                        seeyonPoc.informationLeakageVulScan();
                        break;
                    case "SQL注入":
                        seeyonPoc.sqlInjectVulScan();
                        break;
                    case "htmlofficeservlet任意文件写入":
                        seeyonPoc.fileUploadVulScan();
                        break;
                    default:
                        Alert alert = new Alert(Alert.AlertType.WARNING);
                        alert.setTitle("错误");
                        alert.setContentText("初始化错误或者系统异常！！！！！");
                        alert.setHeaderText("信息出错");
                        alert.showAndWait();
                        break;
                }
            }).start();
        }
    }

    /**
     * 扫描通达OA漏洞方法
     */
    @FXML
    public void scanTdVul() {
        if (tdUrlTextField.getText().isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.WARNING);
            alert.setTitle("错误");
            alert.setContentText("目标地址为空或者输入错误！！！！！");
            alert.setHeaderText("目标地址错误");
            alert.showAndWait();
        } else {
            new Thread(() -> {
                TongdaPoc tongdaPoc = new TongdaPoc(this.proxy, tdUrlTextField.getText(), this);
                switch (tdPocTypeChoiceBox.getValue()) {
                    case "文件包含GetShell":
                        tongdaPoc.fileContainVulScan();
                        break;
                    case "文件上传GetShell":
                        tongdaPoc.fileUploadVulScan();
                        break;
                    case "测试方法":
                        tongdaPoc.testVul();
                        break;
                    default:
                        Alert alert = new Alert(Alert.AlertType.WARNING);
                        alert.setTitle("错误");
                        alert.setContentText("初始化错误或者系统异常！！！！！");
                        alert.setHeaderText("信息出错");
                        alert.showAndWait();
                        break;
                }
            }).start();
        }
    }

    @FXML
    public void seeyonAppendVulInfo(String vulInfo) {
        this.seeyonScanInfoTextArea.appendText(vulInfo + "\n");
    }

    @FXML
    public void tdAppendVulInfo(String vulInfo) {
        this.tdScanInfoTextArea.appendText(vulInfo + "\n");
    }

    @FXML
    public void seeyonClearVulInfo() {
        seeyonScanInfoTextArea.clear();
    }

    @FXML
    public void tdClearVulInfo() {
        tdScanInfoTextArea.clear();
    }


}