package org.omnifaces.elios.config.data;

import java.util.HashMap;

public class InterceptEntry {
    String defaultClientID;
    String defaultServerID;
    HashMap idMap;

    public InterceptEntry(String defaultClientID, String defaultServerID, HashMap idMap) {
        this.defaultClientID = defaultClientID;
        this.defaultServerID = defaultServerID;
        this.idMap = idMap;
    }

    public HashMap getIdMap() {
        return idMap;
    }

    public void setIdMap(HashMap map) {
        idMap = map;
    }

    public String getDefaultClientID() {
        return defaultClientID;
    }

    public String getDefaultServerID() {
        return defaultServerID;
    }
}
