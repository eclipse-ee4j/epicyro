# Epicyro

Eclipse Epicyro implements [Jakarta Authentication](https://jakarta.ee/specifications/authentication/3.0/), a technology that defines a general low-level SPI for authentication mechanisms, which are controllers that interact with a caller and a container’s environment to obtain the caller’s credentials, validate these, and pass an authenticated identity (such as name and groups) to the container.

Jakarta Authentication consists of several profiles, with each profile telling how a specific container (such as Jakarta Servlet) can integrate with- and adapt to this SPI.

[Website](https://eclipse-ee4j.github.io/epicyro) (wip)

Building
--------

Epicyro can be built by executing the following from the project root:

``mvn clean package``

