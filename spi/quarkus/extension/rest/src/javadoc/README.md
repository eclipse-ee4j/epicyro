# Epicyro Quarkus extension - REST

This hidden extension has no API. It is added automatically by the Epicyro Quarkus extension (`quarkus-epicyro`)
when the application uses Quarkus REST, and brings in `quarkus-rest-servlet`, so that REST requests run through the
Servlet container and a ServerAuthModule sees them.
