package com.communityguardian.service;

import com.communityguardian.exception.ValidationException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;

public class IntegrityService {
    private static final String PREFIX = "INTEGRITYv1";

    public static void writeSignature(Path dataPath) {
        try {
            if (!Files.exists(dataPath)) {
                return;
            }
            KeyService.KeyRef active = KeyService.activeIntegrityKey();
            byte[] data = Files.readAllBytes(dataPath);
            String sig = hmac(active.key, data);
            String envelope = PREFIX + ":" + active.version + ":" + sig;
            Files.writeString(sigPath(dataPath), envelope, StandardCharsets.UTF_8);
        } catch (Exception ex) {
            throw new ValidationException("failed to write integrity signature for " + dataPath);
        }
    }

    public static void verifyIfPresent(Path dataPath) {
        try {
            Path sigPath = sigPath(dataPath);
            if (!Files.exists(dataPath) || !Files.exists(sigPath)) {
                return;
            }
            String envelope = Files.readString(sigPath, StandardCharsets.UTF_8).trim();
            String[] parts = envelope.split(":", 3);
            if (parts.length != 3 || !PREFIX.equals(parts[0])) {
                throw new ValidationException("invalid integrity signature format for " + dataPath);
            }

            String version = parts[1];
            String expected = parts[2];
            Map<String, String> keys = KeyService.allIntegrityKeys();
            String key = keys.get(version);
            if (key == null) {
                throw new ValidationException("missing integrity key version: " + version);
            }

            byte[] data = Files.readAllBytes(dataPath);
            String actual = hmac(key, data);
            if (!safeEquals(expected, actual)) {
                throw new ValidationException("tamper detected: integrity check failed for " + dataPath);
            }
        } catch (ValidationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new ValidationException("integrity verification failed for " + dataPath);
        }
    }

    private static Path sigPath(Path dataPath) {
        return Path.of(dataPath.toString() + ".sig");
    }

    private static String hmac(String key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return Base64.getEncoder().encodeToString(mac.doFinal(data));
    }

    private static boolean safeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        if (a.length() != b.length()) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length(); i++) {
            diff |= a.charAt(i) ^ b.charAt(i);
        }
        return diff == 0;
    }
}
