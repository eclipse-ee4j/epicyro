package org.glassfish.epicyro.quarkus.test;

import jakarta.security.auth.message.config.AuthConfigFactory;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;

/**
 * Registers {@link TestServerAuthModule} for this web application, the standard Jakarta Authentication way.
 */
@WebListener
public class SamRegistrationListener implements ServletContextListener {

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        AuthConfigFactory.getFactory().registerServerAuthModule(new TestServerAuthModule(), sce.getServletContext());
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        AuthConfigFactory.getFactory().removeServerAuthModule(sce.getServletContext());
    }
}
