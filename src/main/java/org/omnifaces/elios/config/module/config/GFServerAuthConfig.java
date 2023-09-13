package org.omnifaces.elios.config.module.config;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;

import org.omnifaces.elios.config.module.configprovider.GFServerConfigProvider.ModuleInfo;
import org.omnifaces.elios.config.module.context.GFServerAuthContext;

public class GFServerAuthConfig extends GFAuthConfig implements ServerAuthConfig {

    protected GFServerAuthConfig(AuthConfigProvider provider, String layer, String appContext, CallbackHandler handler) {
        super(provider, layer, appContext, handler, SERVER);
    }

    public ServerAuthContext getAuthContext(String authContextID, Subject serviceSubject, Map properties) throws AuthException {
        ServerAuthContext serverAuthContext = null;
        ModuleInfo moduleInfo = getModuleInfo(authContextID, properties);

        if (moduleInfo != null && moduleInfo.getModule() != null) {
            Object moduleObj = moduleInfo.getModule();
            Map map = moduleInfo.getMap();
            if (moduleObj instanceof ServerAuthModule) {
                serverAuthContext = new GFServerAuthContext(this, (ServerAuthModule) moduleObj, map);
            }
        }

        return serverAuthContext;
    }
}