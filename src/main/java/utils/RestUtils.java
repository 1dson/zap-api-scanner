package utils;

import com.sun.istack.internal.NotNull;
import io.restassured.config.RestAssuredConfig;
import io.restassured.config.SSLConfig;
import io.restassured.http.ContentType;
import io.restassured.response.ValidatableResponse;

import java.util.Map;

import static io.restassured.RestAssured.given;

public class RestUtils {

    private static ValidatableResponse response;

    public static ValidatableResponse getThroughProxy(@NotNull String proxyURI, @NotNull int proxyPort, @NotNull String serviceEndPoint, @NotNull Map<String, String> headers) {
        response = given()
                .urlEncodingEnabled(true)
                .log().all()
                .headers(headers)
                .proxy(proxyURI,proxyPort)
                .when().config(RestAssuredConfig.config().sslConfig(new SSLConfig().relaxedHTTPSValidation().allowAllHostnames()))
                .get(serviceEndPoint)
                .then();
        return response;
    }


    public static ValidatableResponse postThroughProxy(@NotNull String proxyURI,@NotNull int proxyPort,@NotNull Object requestBody, @NotNull String serviceEndPoint, @NotNull Map<String, String> headers) {
        response = given()
                .urlEncodingEnabled(true)
                .log().all()
                .contentType(ContentType.JSON)
                .headers(headers)
                .proxy(proxyURI,proxyPort)
                .body(requestBody)
                .when().config(RestAssuredConfig.config().sslConfig(new SSLConfig().relaxedHTTPSValidation().allowAllHostnames()))
                .post(serviceEndPoint)
                .then();
        return response;
    }

    public static ValidatableResponse putThroughProxy(@NotNull String proxyURI,@NotNull int proxyPort, @NotNull Object requestBody, @NotNull String serviceEndPoint, @NotNull Map<String, String> headers) {
        response = given()
                .urlEncodingEnabled(true)
                .log().all()
                .contentType(ContentType.JSON)
                .headers(headers)
                .proxy(proxyURI,proxyPort)
                .body(requestBody)
                .when().config(RestAssuredConfig.config().sslConfig(new SSLConfig().relaxedHTTPSValidation().allowAllHostnames()))
                .put(serviceEndPoint)
                .then();
        return response;
    }
}