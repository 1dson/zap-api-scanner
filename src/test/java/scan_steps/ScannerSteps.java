package scan_steps;


import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import com.typesafe.config.ConfigRenderOptions;
import io.restassured.response.ValidatableResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.After;
import org.junit.Test;
import org.zaproxy.clientapi.core.ClientApiException;
import scanner.ScannerMethods;
import utils.RestUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ScannerSteps {


    private static final Logger LOGGER = LogManager.getLogger(ScannerSteps.class);

    private ScannerMethods scanner = new ScannerMethods();
    private ValidatableResponse apiResponse;

    private Config config = ConfigFactory.defaultApplication();

    private String baseURL = config.getString("api.baseURL");


    private final String SCAN_REPORT_NAME = config.getString("scan.reportName");
    private final String CONTEXT_NAME = config.getString("scan.contextName");

    private List<String> resources = config.getStringList("api.resources");
    private List<String> calls = config.getStringList("api.call");
    private List<String> policies = config.getStringList("scan.policies");

    //ConfigRenderOptions.concise() parses an object into JSON
    private Object putPayLoad = config.root().toConfig().getObject("api.payload.put").render(ConfigRenderOptions.concise());
    private Object postPayLoad = config.root().toConfig().getObject("api.payload.post").render(ConfigRenderOptions.concise());

    private Map<String, String> requestKey = new HashMap<>();

    {
        requestKey.put("x-api-key", config.getString("api.apiKey"));
    }


    @Test
    public void executeTests() throws Exception {
        if (!baseURL.isEmpty() && (!resources.isEmpty()) && (!calls.isEmpty())) {
            for (String call : calls) {
                switch (call) {
                    case "get":
                    case "put":
                    case "post":
                        scanEndPoints();
                        break;
                    default:
                        throw new Exception("call not supported - ONLY PUT, POST and GET are accepted");
                }
            }
        } else {
            LOGGER.info("Please make sure that the BASE URL, RESOURCES and/or CALLS are not empty");
        }

    }


    private void scanEndPoints() throws Exception {
        for (String verb : calls) {
            for (String resource : resources) {
                switch (verb) {
                    case "get":
                        apiResponse = RestUtils.getThroughProxy("localhost", 8090, baseURL.concat(resource), requestKey);
                        break;
                    case "put":
                        apiResponse = RestUtils.putThroughProxy("localhost", 8090, putPayLoad, baseURL.concat(resource), requestKey);
                        break;
                    case "post":
                        apiResponse = RestUtils.postThroughProxy("localhost", 8090, postPayLoad, baseURL.concat(resource), requestKey);
                        break;
                }
                try {
                    scanner.createContext(CONTEXT_NAME);
                } catch (ClientApiException e) {
                    scanner.useExistingContext(CONTEXT_NAME);
                }
                scanner.includeInContext(CONTEXT_NAME, baseURL);
                scanner.enableAllPassiveScanners();
                scanner.performSpiderCrawl(baseURL, CONTEXT_NAME);
                for (String policy : policies) {
                    scanner.enableActiveScannerByName(policy);
                    scanner.setScannerAttackStrength(policy, "insane");
                    scanner.performActiveAttack(baseURL);
                }
            }
            scanner.createReport(SCAN_REPORT_NAME, baseURL);
        }
    }

    @After
    public void tearDown(){
        scanner.stopZap();
    }
}