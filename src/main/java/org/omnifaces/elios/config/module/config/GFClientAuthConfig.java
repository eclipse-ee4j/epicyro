package org.omnifaces.elios.config.module.config;

public class GFClientAuthConfig extends GFAuthConfig implements ClientAuthConfig {

    protected GFClientAuthConfig(AuthConfigProvider provider, String layer, String appContext, CallbackHandler handler) {
        super(provider, layer, appContext, handler, CLIENT);
    }

    public ClientAuthContext getAuthContext(String authContextID, Subject clientSubject, Map properties) throws AuthException {
        ClientAuthContext clientAuthContext = null;
        ModuleInfo moduleInfo = getModuleInfo(authContextID, properties);

        if (moduleInfo != null && moduleInfo.getModule() != null) {
            Object moduleObj = moduleInfo.getModule();
            Map map = moduleInfo.getMap();
            if (moduleObj instanceof ClientAuthModule) {
                clientAuthContext = new GFClientAuthContext(this, (ClientAuthModule) moduleObj, map);
            }
        }

        return clientAuthContext;
    }
}