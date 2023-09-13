package org.omnifaces.elios.config.module.context;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;

import org.omnifaces.elios.config.delegate.MessagePolicyDelegate;
import org.omnifaces.elios.config.helper.EpochCarrier;
import org.omnifaces.elios.config.helper.ModulesManager;

public class ServerAuthContextImpl implements ServerAuthContext {

    final static AuthStatus[] vR_SuccessValue = { AuthStatus.SUCCESS, AuthStatus.SEND_SUCCESS };
    final static AuthStatus[] sR_SuccessValue = { AuthStatus.SEND_SUCCESS };
    HashMap<String, HashMap<Integer, ServerAuthContext>> contextMap;
    ModulesManager acHelper;

    private String loggerName;

    private String authContextID;
    
    EpochCarrier providerEpoch;
    long epoch;
    MessagePolicyDelegate mpDelegate;
    String layer;
    String appContext;
    CallbackHandler cbh;
    private ReentrantReadWriteLock instanceReadWriteLock = new ReentrantReadWriteLock();
    
    final Map properties;
    
    public ServerAuthContextImpl(Map properties) {
        this.properties = properties;
    }

    ServerAuthModule[] module = init();

    ServerAuthModule[] init() {
        ServerAuthModule[] m;
        try {
            m = acHelper.getModules(new ServerAuthModule[0], authContextID);
        } catch (AuthException ae) {
            logIfLevel(Level.SEVERE, ae, "ServerAuthContext: ", authContextID, "of AppContext: ", getAppContext(), "unable to load server auth modules");
            throw new RuntimeException(ae);
        }

        MessagePolicy requestPolicy = mpDelegate.getRequestPolicy(authContextID, properties);
        MessagePolicy responsePolicy = mpDelegate.getResponsePolicy(authContextID, properties);

        boolean noModules = true;
        for (int i = 0; i < m.length; i++) {
            if (m[i] != null) {
                if (isLoggable(Level.FINE)) {
                    logIfLevel(Level.FINE, null, "ServerAuthContext: ", authContextID, "of AppContext: ", getAppContext(), "initializing module");
                }
                noModules = false;
                try {
                    checkMessageTypes(m[i].getSupportedMessageTypes());
                    m[i].initialize(requestPolicy, responsePolicy, cbh, acHelper.getInitProperties(i, properties));
                } catch (AuthException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        }
        if (noModules) {
            logIfLevel(Level.WARNING, null, "ServerAuthContext: ", authContextID, "of AppContext: ", getAppContext(), "contains no Auth Modules");
        }
        return m;
    }

    @Override
    public AuthStatus validateRequest(MessageInfo arg0, Subject arg1, Subject arg2) throws AuthException {
        AuthStatus[] status = new AuthStatus[module.length];
        for (int i = 0; i < module.length; i++) {
            if (module[i] == null) {
                continue;
            }
            if (isLoggable(Level.FINE)) {
                logIfLevel(Level.FINE, null, "ServerAuthContext: ", authContextID, "of AppContext: ", getAppContext(), "calling vaidateRequest on module");
            }
            status[i] = module[i].validateRequest(arg0, arg1, arg2);
            if (acHelper.exitContext(vR_SuccessValue, i, status[i])) {
                return acHelper.getReturnStatus(vR_SuccessValue, AuthStatus.SEND_FAILURE, status, i);
            }
        }
        return acHelper.getReturnStatus(vR_SuccessValue, AuthStatus.SEND_FAILURE, status, status.length - 1);
    }

    @Override
    public AuthStatus secureResponse(MessageInfo arg0, Subject arg1) throws AuthException {
        AuthStatus[] status = new AuthStatus[module.length];
        for (int i = 0; i < module.length; i++) {
            if (module[i] == null) {
                continue;
            }
            if (isLoggable(Level.FINE)) {
                logIfLevel(Level.FINE, null, "ServerAuthContext: ", authContextID, "of AppContext: ", getAppContext(), "calling secureResponse on module");
            }
            status[i] = module[i].secureResponse(arg0, arg1);
            if (acHelper.exitContext(sR_SuccessValue, i, status[i])) {
                return acHelper.getReturnStatus(sR_SuccessValue, AuthStatus.SEND_FAILURE, status, i);
            }
        }
        return acHelper.getReturnStatus(sR_SuccessValue, AuthStatus.SEND_FAILURE, status, status.length - 1);
    }

    @Override
    public void cleanSubject(MessageInfo arg0, Subject arg1) throws AuthException {
        for (int i = 0; i < module.length; i++) {
            if (module[i] == null) {
                continue;
            }
            if (isLoggable(Level.FINE)) {
                logIfLevel(Level.FINE, null, "ServerAuthContext: ", authContextID, "of AppContext: ", getAppContext(), "calling cleanSubject on module");
            }
            module[i].cleanSubject(arg0, arg1);
        }
    }

    

    protected boolean isLoggable(Level level) {
        Logger logger = Logger.getLogger(loggerName);
        return logger.isLoggable(level);
    }

    protected void logIfLevel(Level level, Throwable t, String... msgParts) {
        Logger logger = Logger.getLogger(loggerName);
        if (logger.isLoggable(level)) {
            StringBuffer msgB = new StringBuffer("");
            for (String m : msgParts) {
                msgB.append(m);
            }
            String msg = msgB.toString();
            if (!msg.isEmpty() && t != null) {
                logger.log(level, msg, t);
            } else if (!msg.isEmpty()) {
                logger.log(level, msg);
            }
        }
    }
    
    public String getAppContext() {
        return appContext;
    }
    
    protected void checkMessageTypes(Class[] supportedMessageTypes) throws AuthException {
        Class[] requiredMessageTypes = mpDelegate.getMessageTypes();
        for (Class requiredType : requiredMessageTypes) {
            boolean supported = false;
            for (Class supportedType : supportedMessageTypes) {
                if (requiredType.isAssignableFrom(supportedType)) {
                    supported = true;
                }
            }
            if (!supported) {
                throw new AuthException("module does not support message type: " + requiredType.getName());
            }
        }
    }

}
