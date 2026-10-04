package org.glassfish.epicyro.quarkus.test;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Marks every response that went through the Undertow servlet pipeline, so tests can check that REST requests are
 * routed through Servlet rather than straight from Vert.x.
 */
@WebFilter("/*")
public class ServletMarkerFilter extends HttpFilter {

    public static final String VIA_SERVLET_HEADER = "X-Via-Servlet";

    @Override
    protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        response.setHeader(VIA_SERVLET_HEADER, "true");
        chain.doFilter(request, response);
    }
}
