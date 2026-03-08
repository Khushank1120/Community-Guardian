package com.communityguardian.service;

import com.communityguardian.exception.ValidationException;

import java.util.HashMap;
import java.util.Map;

public class KeyService {
    public static class KeyRef {
        public final String version;
        public final String key;

        public KeyRef(String version, String key) {
            this.version = version;
            this.key = key;
        }
    }

    public static KeyRef activeUsersKey() {
        return activeKey("USERS_DB_KEYS", "users.db.keys", "USERS_DB_ACTIVE_VERSION", "users.db.active", "USERS_DB_KEY", "users.db.key");
    }

    public static Map<String, String> allUsersKeys() {
        return allKeys("USERS_DB_KEYS", "users.db.keys", "USERS_DB_KEY", "users.db.key");
    }

    public static KeyRef activeIncidentKey() {
        return activeKey("INCIDENT_DATA_KEYS", "incident.data.keys", "INCIDENT_DATA_ACTIVE_VERSION", "incident.data.active", "INCIDENT_DATA_KEY", "incident.data.key");
    }

    public static Map<String, String> allIncidentKeys() {
        return allKeys("INCIDENT_DATA_KEYS", "incident.data.keys", "INCIDENT_DATA_KEY", "incident.data.key");
    }

    public static KeyRef activeIntegrityKey() {
        return activeKey("DATA_INTEGRITY_KEYS", "data.integrity.keys", "DATA_INTEGRITY_ACTIVE_VERSION", "data.integrity.active", "DATA_INTEGRITY_KEY", "data.integrity.key");
    }

    public static Map<String, String> allIntegrityKeys() {
        return allKeys("DATA_INTEGRITY_KEYS", "data.integrity.keys", "DATA_INTEGRITY_KEY", "data.integrity.key");
    }

    private static KeyRef activeKey(
        String keysEnv,
        String keysProp,
        String activeEnv,
        String activeProp,
        String singleEnv,
        String singleProp
    ) {
        Map<String, String> keys = allKeys(keysEnv, keysProp, singleEnv, singleProp);
        String active = read(activeEnv, activeProp);
        if (active == null || active.isBlank()) {
            if (keys.size() == 1) {
                String only = keys.keySet().iterator().next();
                return new KeyRef(only, keys.get(only));
            }
            throw new ValidationException("active key version is required: " + activeEnv);
        }
        String key = keys.get(active);
        if (key == null) {
            throw new ValidationException("active key version not found in key ring: " + active);
        }
        return new KeyRef(active, key);
    }

    private static Map<String, String> allKeys(String keysEnv, String keysProp, String singleEnv, String singleProp) {
        Map<String, String> out = new HashMap<>();
        String ring = read(keysEnv, keysProp);
        if (ring != null && !ring.isBlank()) {
            String[] items = ring.split(";");
            for (String item : items) {
                String part = item.trim();
                if (part.isEmpty()) {
                    continue;
                }
                int idx = part.indexOf(':');
                if (idx <= 0 || idx >= part.length() - 1) {
                    throw new ValidationException("invalid key ring item format, expected version:key");
                }
                String version = part.substring(0, idx).trim();
                String key = part.substring(idx + 1).trim();
                validateKey(version, key, keysEnv);
                out.put(version, key);
            }
        }

        if (out.isEmpty()) {
            String single = read(singleEnv, singleProp);
            if (single == null || single.length() < 12) {
                throw new ValidationException("missing or weak encryption key: " + singleEnv + " (min 12 chars)");
            }
            out.put("v1", single);
        }
        return out;
    }

    private static void validateKey(String version, String key, String source) {
        if (version.isBlank()) {
            throw new ValidationException("invalid key version in " + source);
        }
        if (key.length() < 12) {
            throw new ValidationException("weak key in " + source + " for version " + version + " (min 12 chars)");
        }
    }

    private static String read(String env, String prop) {
        String p = System.getProperty(prop);
        if (p != null && !p.isBlank()) {
            return p;
        }
        String e = System.getenv(env);
        if (e != null && !e.isBlank()) {
            return e;
        }
        return null;
    }
}
