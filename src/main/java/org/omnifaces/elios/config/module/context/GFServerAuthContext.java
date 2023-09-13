package org.omnifaces.elios.config.module.context;
public class GFServerAuthContext implements ServerAuthContext {

        private GFServerAuthConfig config;
        private ServerAuthModule module;

        private Map map;
        boolean managesSession = false;

        GFServerAuthContext(GFServerAuthConfig config, ServerAuthModule module, Map map) {
            this.config = config;
            this.module = module;
            this.map = map;
        }

        GFServerAuthContext(GFServerAuthConfig config, Map map) {
            this.config = config;
            this.module = null;
            this.map = map;
            if (map != null) {
                String msStr = (String) map.get(GFServerConfigProvider.MANAGES_SESSIONS_OPTION);
                if (msStr != null) {
                    managesSession = Boolean.valueOf(msStr);
                }
            }
        }

        // for old modules
        private static void _setCallerPrincipals(Subject s, CallbackHandler handler, Subject pvcSubject) throws AuthException {

            if (handler != null) { // handler should be non-null
                Set<Principal> ps = s.getPrincipals();
                if (ps == null || ps.isEmpty()) {
                    return;
                }
                Iterator<Principal> it = ps.iterator();

                Callback[] callbacks = new Callback[] { new CallerPrincipalCallback(s, it.next().getName()) };
                if (pvcSubject != null) {
                    s.getPrincipals().addAll(pvcSubject.getPrincipals());
                }

                try {
                    handler.handle(callbacks);
                } catch (Exception e) {
                    AuthException aex = new AuthException();
                    aex.initCause(e);
                    throw aex;
                }
            }
        }

        // for old modules
        private static void setCallerPrincipals(final Subject s, final CallbackHandler handler, final Subject pvcSubject) throws AuthException {
            if (System.getSecurityManager() == null) {
                _setCallerPrincipals(s, handler, pvcSubject);
            } else {
                try {
                    AccessController.doPrivileged(new PrivilegedExceptionAction() {
                        public Object run() throws Exception {
                            _setCallerPrincipals(s, handler, pvcSubject);
                            return null;
                        }
                    });
                } catch (PrivilegedActionException pae) {
                    Throwable cause = pae.getCause();
                    AuthException aex = new AuthException();
                    aex.initCause(cause);
                    throw aex;
                }
            }
        }

        public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
            if (module != null) {
                return module.validateRequest(messageInfo, clientSubject, serviceSubject);
            }

            throw new AuthException();

        }

        public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
            if (module != null) {
                return module.secureResponse(messageInfo, serviceSubject);
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