package org.omnifaces.elios.config.module.config;

import java.security.KeyStore.Entry;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.config.AuthConfig;
import javax.security.auth.message.config.AuthConfigProvider;

import org.omnifaces.elios.config.helper.AuthMessagePolicy;
import org.omnifaces.elios.config.helper.HttpServletConstants;
import org.omnifaces.elios.config.module.configprovider.GFServerConfigProvider;
import org.omnifaces.elios.config.module.configprovider.GFServerConfigProvider.ModuleInfo;

public class GFAuthConfig implements AuthConfig {
        protected AuthConfigProvider provider = null;
        protected String layer = null;
        protected String appContext = null;
        protected CallbackHandler handler = null;
        protected String type = null;
        protected String providerID = null;
        protected boolean init = false;
        protected boolean onePolicy = false;

        protected GFAuthConfig(AuthConfigProvider provider, String layer, String appContext, CallbackHandler handler, String type) {
            this.provider = provider;
            this.layer = layer;
            this.appContext = appContext;
            this.type = type;
            if (handler == null) {
                handler = AuthMessagePolicy.getDefaultCallbackHandler();
//		this.newHandler = true;
            }
            this.handler = handler;
        }

        /**
         * Get the message layer name of this authentication context configuration object.
         *
         * @return the message layer name of this configuration object, or null if the configuration object pertains to an
         * unspecified message layer.
         */
        public String getMessageLayer() {
            return layer;
        }

        /**
         * Get the application context identifier of this authentication context configuration object.
         *
         * @return the String identifying the application context of this configuration object or null if the configuration
         * object pertains to an unspecified application context.
         */
        public String getAppContext() {
            return appContext;
        }

        /**
         * Get the authentication context identifier corresponding to the request and response objects encapsulated in
         * messageInfo.
         * 
         * See method AuthMessagePolicy. getHttpServletPolicies() for more details on why this method returns the String's
         * "true" or "false" for AuthContextID.
         *
         * @param messageInfo a contextual Object that encapsulates the client request and server response objects.
         *
         * @return the authentication context identifier corresponding to the encapsulated request and response objects, or
         * null.
         * 
         *
         * @throws IllegalArgumentException if the type of the message objects incorporated in messageInfo are not compatible
         * with the message types supported by this authentication context configuration object.
         */
        public String getAuthContextID(MessageInfo messageInfo) {
            if (GFServerConfigProvider.HTTPSERVLET.equals(layer)) {
                String isMandatoryStr = (String) messageInfo.getMap().get(HttpServletConstants.IS_MANDATORY);
                return Boolean.valueOf(isMandatoryStr).toString();
            } else {
                return null;
            }
        }

        // we should be able to replace the following with a method on packet

        /**
         * Causes a dynamic anthentication context configuration object to update the internal state that it uses to process
         * calls to its <code>getAuthContext</code> method.
         *
         * @exception AuthException if an error occured during the update.
         *
         * @exception SecurityException if the caller does not have permission to refresh the configuration object.
         */
        public void refresh() {
            loadParser(provider, factory, null);
        }

        /**
         * Used to determine whether or not the <code>getAuthContext</code> method of the authentication context configuration
         * will return null for all possible values of authentication context identifier.
         *
         * @return false when <code>getAuthContext</code> will return null for all possible values of authentication context
         * identifier. Otherwise, this method returns true.
         */
        public boolean isProtected() {
            // XXX TBD
            return true;
        }

        CallbackHandler getCallbackHandler() {
            return handler;
        }

        protected ModuleInfo getModuleInfo(String authContextID, Map properties) throws AuthException {
            if (!init) {
                initialize(properties);
            }

            MessagePolicy[] policies = null;

            if (GFServerConfigProvider.HTTPSERVLET.equals(layer)) {

                policies = AuthMessagePolicy.getHttpServletPolicies(authContextID);

            }

            MessagePolicy requestPolicy = policies[0];
            MessagePolicy responsePolicy = policies[1];

            Entry entry = getEntry(layer, providerID, requestPolicy, responsePolicy, type);

            return (entry != null) ? createModuleInfo(entry, handler, type, properties) : null;
        }

        // lazy initialize this as SunWebApp is not available in
        // RealmAdapter creation
        private void initialize(Map properties) {
            if (!init) {

                if (GFServerConfigProvider.HTTPSERVLET.equals(layer)) {
                    providerID = null;
                    onePolicy = true;
                }

                // handlerContext need to be explictly set by caller
                init = true;
            }
        }
    }

   

    

    