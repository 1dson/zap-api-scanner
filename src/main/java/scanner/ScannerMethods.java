package scanner;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.net.URLEncoder;
import java.time.Instant;
import java.util.Iterator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ApiResponseList;
import org.zaproxy.clientapi.core.ApiResponseSet;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

public class ScannerMethods {
    private static final String ZAP_ADDRESS = "127.0.0.1";
    private static final int ZAP_PORT = 8090;
    private static String scanId = null;
    private static int progress;
    private ClientApi clientApi = new ClientApi("127.0.0.1", 8090);
    private ApiResponse response;
    private String reportURL;
    private final String CONTEXT_ID = "1";
    private final String DEFAULT_POLICY = "Default Policy";
    private static final Logger LOGGER = LogManager.getLogger(ScannerMethods.class);

    public ScannerMethods() {
    }

    private String createReportSummaryTable() {
        StringBuilder sb = new StringBuilder();
        sb.append("<table width=45% border=0>").append("<tr bgcolor=#666666>").append("<td width=45% height=24>").append("<strong>").append("<font color=#FFFFFF size=2 face=Arial, Helvetica, sans-serif>URLs SCANNED").append("</font></strong></td></tr>").append("<tr bgcolor=#e8e8e8>").append(String.format("<td><font size=2 face=Arial, Helvetica, sans-serif><a href=#%s>%s</a></font></td>", this.reportURL, this.reportURL)).append("</tr>").append("<p></p>").append("<p></p>").append("<p></p>").append("<p></p>");
        return sb.toString();
    }

    private String headersAndResponseSummaryTable() throws ClientApiException {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("<table width=45% border=0>").append("<tr bgcolor=#666666>").append("<h3>Server Requests and Responses</h3>").append("<div class=spacer></div>").append("<td width=50%>Request</td>").append("<td width=50%><p>Response</p></td>");
        this.response = this.clientApi.core.messages(this.reportURL, "-1", "-1");
        ApiResponseList apiResponseList = (ApiResponseList)this.response;
        Iterator var3 = apiResponseList.getItems().iterator();

        while(var3.hasNext()) {
            ApiResponse apiResponse = (ApiResponse)var3.next();
            ApiResponseSet serverResponse = (ApiResponseSet)apiResponse;
            stringBuilder.append("<tr bgcolor=#e8e8e8>").append(String.format("<td width=100><p>%s</p></td>", serverResponse.getStringValue("requestHeader"))).append(String.format("<td width=100><p>%s</p></td>", serverResponse.getStringValue("responseHeader"))).append("</tr>");
        }

        return stringBuilder.toString();
    }

    public void createReport(String reportName, String reportURL) throws Exception {
        this.reportURL = reportURL;
        File dir = new File("Reports");
        if (!dir.exists()) {
            dir.mkdir();
        }

        File reportPath = new File(String.format(dir + "/" + reportName + "_%d.html", Instant.now().getEpochSecond()));

        try {
            PrintStream out = new PrintStream(new FileOutputStream(reportPath));
            Throwable var6 = null;

            try {
                out.print(this.createReportSummaryTable());
                out.print(new String(this.clientApi.core.htmlreport()));
                out.print(this.headersAndResponseSummaryTable());
            } catch (Throwable var16) {
                var6 = var16;
                throw var16;
            } finally {
                if (out != null) {
                    if (var6 != null) {
                        try {
                            out.close();
                        } catch (Throwable var15) {
                            var6.addSuppressed(var15);
                        }
                    } else {
                        out.close();
                    }
                }

            }
        } catch (FileNotFoundException var18) {
            var18.printStackTrace();
        }

    }

    public void downLoadLatestRelease() throws Exception {
        this.clientApi.autoupdate.downloadLatestRelease();
    }

    public void stopZap() {
        try {
            this.clientApi.core.shutdown();
        } catch (ClientApiException var2) {
            var2.printStackTrace();
        }

    }

    public void excludeUrlFromSpiderScan(String urlRegex) throws Exception {
        this.clientApi.spider.excludeFromScan(urlRegex);
    }

    public void excludeUrlFromActiveScan(String urlRegex) throws Exception {
        this.clientApi.ascan.excludeFromScan(urlRegex);
    }

    public void createContext(String CONTEXT_NAME) throws Exception {
        this.clientApi.context.newContext(CONTEXT_NAME);
    }

    public void useExistingContext(String CONTEXT_NAME) throws ClientApiException {
        this.clientApi.context.context(CONTEXT_NAME);
    }

    public void includeInContext(String CONTEXT_NAME, String url) throws ClientApiException {
        this.clientApi.context.includeInContext(CONTEXT_NAME, url);
    }

    public void createZapUser(String siteUrl, String loginRequest, String authentication) throws Exception {
        String url = String.format("loginUrl=%s", siteUrl + "&loginRequestData=" + URLEncoder.encode(loginRequest, "UTF-8"));
        this.clientApi.authentication.setAuthenticationMethod("1", authentication, url);
        this.clientApi.users.newUser("1", "test_user");
        this.clientApi.users.setUserEnabled("1", "0", "true");
        this.clientApi.forcedUser.setForcedUserModeEnabled(true);
        this.setOptionHandleAntiCSRFTokens(true);
    }

    public void allowAttackOnStart(boolean setStatus) throws ClientApiException {
        this.clientApi.ascan.setOptionAllowAttackOnStart(setStatus);
    }

    public void allowRescan(boolean setStatus) throws ClientApiException {
        this.clientApi.ascan.setOptionRescanInAttackMode(setStatus);
    }

    public void authenticateUser(String username, String password) throws Exception {
        this.clientApi.users.setAuthenticationCredentials("1", "0", String.format("username=%s&password=%s", username, password));
    }

    public void userStatus(String loginIndicator, String logoutIndicator) throws ClientApiException {
        this.clientApi.authentication.setLoggedInIndicator("1", loginIndicator);
        this.clientApi.authentication.setLoggedOutIndicator("1", logoutIndicator);
    }

    public void removeContext() throws ClientApiException {
        this.clientApi.context.removeContext("Default Context");
    }

    public void filterAlerts(String ruleId, String newLevel) throws Exception {
        this.clientApi.alertFilter.addAlertFilter("1", ruleId, newLevel, "http://a.b.c.*", "true", (String)null, "true");
    }

    public String setPolicyId(String policyName) {
        byte var4 = -1;
        switch(policyName.hashCode()) {
            case -2144300495:
                if (policyName.equals("ldap-injection")) {
                    var4 = 14;
                }
                break;
            case -1982249358:
                if (policyName.equals("remote-file-inclusion")) {
                    var4 = 4;
                }
                break;
            case -1937485946:
                if (policyName.equals("parameter-pollution")) {
                    var4 = 20;
                }
                break;
            case -1668980546:
                if (policyName.equals("insecure-http-methods")) {
                    var4 = 19;
                }
                break;
            case -1649460573:
                if (policyName.equals("server-side-code-injection")) {
                    var4 = 7;
                }
                break;
            case -1003218951:
                if (policyName.equals("SOAP XML Injection")) {
                    var4 = 22;
                }
                break;
            case -693845199:
                if (policyName.equals("el-injection")) {
                    var4 = 18;
                }
                break;
            case -660204980:
                if (policyName.equals("script-active-scan-rules")) {
                    var4 = 6;
                }
                break;
            case -201398148:
                if (policyName.equals("server-side-include")) {
                    var4 = 5;
                }
                break;
            case -10816485:
                if (policyName.equals("source-code-disclosure")) {
                    var4 = 11;
                }
                break;
            case 385978565:
                if (policyName.equals("shell-shock")) {
                    var4 = 12;
                }
                break;
            case 507639347:
                if (policyName.equals("crlf-injection")) {
                    var4 = 10;
                }
                break;
            case 517908154:
                if (policyName.equals("padding-oracle")) {
                    var4 = 17;
                }
                break;
            case 1130834846:
                if (policyName.equals("external-redirect")) {
                    var4 = 9;
                }
                break;
            case 1174545319:
                if (policyName.equals("xpath-injection")) {
                    var4 = 15;
                }
                break;
            case 1174745438:
                if (policyName.equals("cross-site-scripting")) {
                    var4 = 1;
                }
                break;
            case 1441806239:
                if (policyName.equals("remote-code-execution")) {
                    var4 = 13;
                }
                break;
            case 1473539992:
                if (policyName.equals("sql-injection")) {
                    var4 = 2;
                }
                break;
            case 1488809043:
                if (policyName.equals("remote-os-command-injection")) {
                    var4 = 8;
                }
                break;
            case 1721992470:
                if (policyName.equals("path-traversal")) {
                    var4 = 3;
                }
                break;
            case 1780274209:
                if (policyName.equals("parameter-tampering")) {
                    var4 = 21;
                }
                break;
            case 1926535207:
                if (policyName.equals("directory-browsing")) {
                    var4 = 0;
                }
                break;
            case 2108613231:
                if (policyName.equals("xml-external-entity")) {
                    var4 = 16;
                }
        }

        String scannerId;
        switch(var4) {
            case 0:
                scannerId = "0";
                break;
            case 1:
                scannerId = "40012,40014,40016,40017";
                break;
            case 2:
                scannerId = "40018";
                break;
            case 3:
                scannerId = "6";
                break;
            case 4:
                scannerId = "7";
                break;
            case 5:
                scannerId = "40009";
                break;
            case 6:
                scannerId = "50000";
                break;
            case 7:
                scannerId = "90019";
                break;
            case 8:
                scannerId = "90020";
                break;
            case 9:
                scannerId = "20019";
                break;
            case 10:
                scannerId = "40003";
                break;
            case 11:
                scannerId = "42,10045,20017";
                break;
            case 12:
                scannerId = "10048";
                break;
            case 13:
                scannerId = "20018";
                break;
            case 14:
                scannerId = "40015";
                break;
            case 15:
                scannerId = "90021";
                break;
            case 16:
                scannerId = "90023";
                break;
            case 17:
                scannerId = "90024";
                break;
            case 18:
                scannerId = "90025";
                break;
            case 19:
                scannerId = "90028";
                break;
            case 20:
                scannerId = "20014";
                break;
            case 21:
                scannerId = "40008";
                break;
            case 22:
                scannerId = "90029";
                break;
            default:
                throw new RuntimeException("No policy id found for: " + policyName);
        }

        return scannerId;
    }

    public void enableAllPassiveScanners() throws Exception {
        this.clientApi.pscan.enableAllScanners();
    }

    public void enableActiveScannerByName(String policyName) throws Exception {
        this.clientApi.ascan.enableScanners(this.setPolicyId(policyName), "Default Policy");
    }

    public void generateRootCA() throws ClientApiException {
        this.clientApi.core.generateRootCA();
    }

    public void setScannerAttackStrength(String policyName, String attackStrength) throws Exception {
        this.clientApi.ascan.setScannerAttackStrength(this.setPolicyId(policyName), attackStrength.toUpperCase(), "Default Policy");
    }

    public void setOptionHandleAntiCSRFTokens(boolean option) throws Exception {
        this.clientApi.ascan.setOptionHandleAntiCSRFTokens(option);
    }

    public void performSpiderCrawlAsUser(String url) throws Exception {
        this.clientApi.spider.setOptionHandleODataParametersVisited(true);
        this.response = this.clientApi.spider.scanAsUser("1", "0", url, (String)null, "true", "true");
        scanId = ((ApiResponseElement)this.response).getValue();

        while(true) {
            progress = Integer.parseInt(((ApiResponseElement)this.clientApi.spider.status(scanId)).getValue());
            LOGGER.info("Static scan in progress : " + progress + "%");
            if (progress >= 100) {
                return;
            }

            try {
                Thread.sleep(5000L);
            } catch (InterruptedException var3) {
                var3.printStackTrace();
            }
        }
    }

    public void performSpiderCrawl(String url, String CONTEXT_NAME) throws Exception {
        this.clientApi.spider.setOptionMaxDepth(0);
        this.clientApi.spider.setOptionAcceptCookies(true);
        this.response = this.clientApi.spider.scan(url, "0", "true", CONTEXT_NAME, "true");
        scanId = ((ApiResponseElement)this.response).getValue();

        while(true) {
            progress = Integer.parseInt(((ApiResponseElement)this.clientApi.spider.status(scanId)).getValue());
            LOGGER.info("Static scan in progress : " + progress + "%");
            if (progress >= 100) {
                return;
            }

            try {
                Thread.sleep(5000L);
            } catch (InterruptedException var4) {
                var4.printStackTrace();
            }
        }
    }

    public void performActiveAttack(String url) throws Exception {
        this.response = this.clientApi.ascan.scan(url, "true", "true", "Default Policy", (String)null, (String)null);
        scanId = ((ApiResponseElement)this.response).getValue();

        while(true) {
            progress = Integer.parseInt(((ApiResponseElement)this.clientApi.ascan.status(scanId)).getValue());
            LOGGER.info("Dynamic scan in progress : " + progress + "%");
            if (progress >= 100) {
                return;
            }

            try {
                Thread.sleep(3000L);
            } catch (InterruptedException var3) {
                var3.printStackTrace();
            }
        }
    }

    public void performActiveAttackAsUser(String url) throws Exception {
        this.response = this.clientApi.ascan.scanAsUser(url, "1", "0", "true", "Default Policy", (String)null, (String)null);
        scanId = ((ApiResponseElement)this.response).getValue();

        while(true) {
            progress = Integer.parseInt(((ApiResponseElement)this.clientApi.ascan.status(scanId)).getValue());
            LOGGER.info("Dynamic scan in progress : " + progress + "%");
            if (progress >= 100) {
                return;
            }

            try {
                Thread.sleep(3000L);
            } catch (InterruptedException var3) {
                var3.printStackTrace();
            }
        }
    }
}