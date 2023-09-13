package org.omnifaces.elios.config.data;

import java.util.Map;

/**
 * A data object contains module object and the corresponding map.
 */
public class ModuleInfo {
    private Object module;
    private Map map;

    ModuleInfo(Object module, Map map) {
        this.module = module;
        this.map = map;
    }

    Object getModule() {
        return module;
    }

    Map getMap() {
        return map;
    }
}