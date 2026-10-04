package org.glassfish.epicyro.quarkus.test;

import io.restassured.RestAssured;
import io.restassured.filter.session.SessionFilter;
import io.restassured.specification.RequestSpecification;

import java.net.URL;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.glassfish.epicyro.quarkus.test.ServletMarkerFilter.VIA_SERVLET_HEADER;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

@ExtendWith(ArquillianExtension.class)
public class HelloResourceTest {

    @ArquillianResource
    URL base;

    @Deployment(testable = false)
    public static WebArchive createDeployment() {
        return ShrinkWrap.create(WebArchive.class)
                .addClasses(
                        HelloResource.class,
                        TestServerAuthModule.class,
                        SamRegistrationListener.class,
                        ServletMarkerFilter.class);
    }

    @Test
    void restRequestGoesThroughServlet() {
        given()
                .when().get("/hello")
                .then()
                .statusCode(200)
                .header(VIA_SERVLET_HEADER, "true")
                .body(is("hello"));
    }

    @Test
    void restEndpointSeesUndertowServletRequest() {
        given()
                .when().get("/hello/servlet-request")
                .then()
                .statusCode(200)
                .body(containsString("io.undertow.servlet"));
    }

    @Test
    void samIsRegisteredWithEpicyro() {
        given()
                .when().get("/hello/sam-registered")
                .then()
                .statusCode(200)
                .body(is("true"));
    }

    @Test
    void samRunsForRestRequest() {
        given()
                .when().get("/hello")
                .then()
                .statusCode(200)
                .header(TestServerAuthModule.INVOKED_HEADER, "true");
    }

    @Test
    void samChallengesForProtectedResource() {
        given()
                .when().get("/hello/protected")
                .then()
                .statusCode(401)
                .header(TestServerAuthModule.INVOKED_HEADER, "true")
                // Run again by the container for @RolesAllowed, not by HttpServletRequest#authenticate()
                .header(TestServerAuthModule.AUTHENTICATION_REQUEST_HEADER, nullValue());
    }

    @Test
    void samAuthenticatesCallerForRolesAllowed() {
        given()
                .header(TestServerAuthModule.USER_HEADER, "arjan")
                .when().get("/hello/protected")
                .then()
                .statusCode(200)
                .body(equalTo("hello arjan"));
    }

    @Test
    void samIdentityIsVisibleOnPublicResource() {
        given()
                .header(TestServerAuthModule.USER_HEADER, "arjan")
                .when().get("/hello/whoami")
                .then()
                .statusCode(200)
                .body(equalTo("arjan"));
    }

    @Test
    void identityDoesNotLeakIntoNextRequest() {
        for (int i = 0; i < 5; i++) {
            given()
                    .header(TestServerAuthModule.USER_HEADER, "arjan")
                    .when().get("/hello/whoami")
                    .then()
                    .body(equalTo("arjan"));

            given()
                    .when().get("/hello/whoami")
                    .then()
                    .statusCode(200)
                    .body(equalTo("anonymous"));
        }
    }

    private RequestSpecification given() {
        return RestAssured.given().baseUri(base.toString());
    }

    @Test
    void logoutCallsCleanSubjectAndClearsIdentity() {
        given()
                .header(TestServerAuthModule.USER_HEADER, "arjan")
                .when().get("/hello/logout")
                .then()
                .statusCode(200)
                .header(TestServerAuthModule.CLEANED_HEADER, "true")
                .body(equalTo("arjan -> anonymous"));
    }

    @Test
    void registeredSessionIsOnlyContinuedWhenTheSamAsks() {
        SessionFilter session = new SessionFilter();

        // Login, and ask the container to remember the caller
        given().filter(session)
                .header(TestServerAuthModule.USER_HEADER, "arjan")
                .header(TestServerAuthModule.REGISTER_HEADER, "true")
                .when().get("/hello/whoami")
                .then()
                .statusCode(200)
                .body(equalTo("arjan"));

        // No credentials, but the SAM continues the registered caller: name and roles are restored
        given().filter(session)
                .header(TestServerAuthModule.CONTINUE_HEADER, "true")
                .when().get("/hello/protected")
                .then()
                .statusCode(200)
                .body(equalTo("hello arjan"));

        // Same session, but the SAM doesn't continue it: anonymous
        given().filter(session)
                .when().get("/hello/whoami")
                .then()
                .statusCode(200)
                .body(equalTo("anonymous"));

        given().filter(session)
                .when().get("/hello/protected")
                .then()
                .statusCode(401);
    }

    @Test
    void logoutEndsRegisteredSession() {
        SessionFilter session = new SessionFilter();

        given().filter(session)
                .header(TestServerAuthModule.USER_HEADER, "arjan")
                .header(TestServerAuthModule.REGISTER_HEADER, "true")
                .when().get("/hello/whoami")
                .then()
                .body(equalTo("arjan"));

        given().filter(session)
                .header(TestServerAuthModule.CONTINUE_HEADER, "true")
                .when().get("/hello/logout")
                .then()
                .statusCode(200)
                .body(equalTo("arjan -> anonymous"));

        // Nothing registered anymore to continue
        given().filter(session)
                .header(TestServerAuthModule.CONTINUE_HEADER, "true")
                .when().get("/hello/whoami")
                .then()
                .statusCode(200)
                .body(equalTo("anonymous"));
    }

    @Test
    void authenticateCallsSamWithAuthenticationRequestKey() {
        // Anonymous at the start of the request; the SAM only authenticates when called for authenticate()
        given()
                .header(TestServerAuthModule.AUTHENTICATE_AS_HEADER, "arjan")
                .when().get("/hello/authenticate")
                .then()
                .statusCode(200)
                .header(TestServerAuthModule.AUTHENTICATION_REQUEST_HEADER, "true")
                .body(equalTo("true arjan"));
    }

    @Test
    void regularRequestIsNoAuthenticationRequest() {
        given()
                .header(TestServerAuthModule.USER_HEADER, "arjan")
                .when().get("/hello/whoami")
                .then()
                .statusCode(200)
                .header(TestServerAuthModule.AUTHENTICATION_REQUEST_HEADER, nullValue());
    }

    @Test
    void authenticateCallsSamForAuthenticatedCaller() {
        // Authenticated at the start of the request; authenticate() must still call the SAM
        given()
                .header(TestServerAuthModule.USER_HEADER, "arjan")
                .when().get("/hello/authenticate")
                .then()
                .statusCode(200)
                .header(TestServerAuthModule.AUTHENTICATION_REQUEST_HEADER, "true")
                .body(equalTo("true arjan"));
    }

    @Test
    void authenticateCanChangeTheCaller() {
        // The SAM establishes a different caller when called for authenticate()
        given()
                .header(TestServerAuthModule.USER_HEADER, "arjan")
                .header(TestServerAuthModule.AUTHENTICATE_AS_HEADER, "bob")
                .when().get("/hello/authenticate")
                .then()
                .statusCode(200)
                .body(equalTo("true bob"));
    }
}
