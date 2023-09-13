package org.omnifaces.elios.config.module.context;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.ClientAuthContext;
import javax.security.auth.message.module.ClientAuthModule;

public class GFClientAuthContext implements ClientAuthContext {

    private GFClientAuthConfig config;
    private ClientAuthModule module;

    GFClientAuthContext(GFClientAuthConfig config, ClientAuthModule module, Map map) {
        this.config = config;
        this.module = module;
    }

    GFClientAuthContext(GFClientAuthConfig config, Map map) {
        this.config = config;
        this.module = null;
    }

    public AuthStatus secureRequest(MessageInfo messageInfo, Subject clientSubject) throws AuthException {
        if (module != null) {
            return module.secureRequest(messageInfo, clientSubject);
        }

        throw new AuthException();
    }

    public AuthStatus validateResponse(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
        if (module != null) {
            return module.validateResponse(messageInfo, clientSubject, serviceSubject);
        }

        throw new AuthException();
    }

    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
        if (module != null) {
            module.cleanSubject(messageInfo, subject);

        } else {
            throw new AuthException();
        }
    }
}