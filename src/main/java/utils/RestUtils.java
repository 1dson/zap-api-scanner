package utils;

import io.restassured.config.RestAssuredConfig;
import io.restassured.config.SSLConfig;
import io.restassured.http.ContentType;
import io.restassured.response.ValidatableResponse;

import java.util.Map;

import static io.restassured.RestAssured.given;

public class RestUtils {

    private static ValidatableResponse response;

    public static ValidatableResponse getThroughProxy(String proxyURI, int proxyPort, String serviceEndPoint, Map<String, String> headers) {
        response = given()
                .urlEncodingEnabled(true)
                .log().all()
                .headers(headers)
                .proxy(proxyURI, proxyPort)
                .when().config(RestAssuredConfig.config().sslConfig(new SSLConfig().relaxedHTTPSValidation().allowAllHostnames()))
                .get(serviceEndPoint)
                .then();
        return response;
    }


    public static ValidatableResponse postThroughProxy(String proxyURI, int proxyPort, Object requestBody, String serviceEndPoint, Map<String, String> headers) {
        response = given()
                .urlEncodingEnabled(true)
                .log().all()
                .contentType(ContentType.JSON)
                .headers(headers)
                .proxy(proxyURI, proxyPort)
                .body(requestBody)
                .when().config(RestAssuredConfig.config().sslConfig(new SSLConfig().relaxedHTTPSValidation().allowAllHostnames()))
                .post(serviceEndPoint)
                .then();
        return response;
    }

    public static ValidatableResponse putThroughProxy(String proxyURI, int proxyPort, Object requestBody, String serviceEndPoint, Map<String, String> headers) {
        response = given()
                .urlEncodingEnabled(true)
                .log().all()
                .contentType(ContentType.JSON)
                .headers(headers)
                .proxy(proxyURI, proxyPort)
                .body(requestBody)
                .when().config(RestAssuredConfig.config().sslConfig(new SSLConfig().relaxedHTTPSValidation().allowAllHostnames()))
                .put(serviceEndPoint)
                .then();
        return response;
    }
}