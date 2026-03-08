package com.communityguardian.auth;

import com.communityguardian.exception.ValidationException;
import com.communityguardian.service.AuditService;
import com.communityguardian.service.IntegrityService;
import com.communityguardian.service.KeyService;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

public class AuthService {
    public static class Session {
        public final String username;
        public final String role;
        public final String defaultLocation;

        public Session(String username, String role, String defaultLocation) {
            this.username = username;
            this.role = role;
            this.defaultLocation = defaultLocation;
        }
    }

    private static final String HEADER = "username,role,salt_b64,password_hash_b64,status,failed_attempts,locked_until,default_location";
    private static final String ENC_PREFIX_V1 = "ENCv1";
    private static final String ENC_PREFIX_V2 = "ENCv2";

    private static final String HASH_SCHEME_PBKDF2 = "pbkdf2_sha256";
    private static final int PASSWORD_HASH_ITERATIONS = 210_000;
    private static final int PASSWORD_HASH_BYTES = 32;

    public static void ensureDefaultUsers(Path usersDbPath) throws IOException {
        if (Files.exists(usersDbPath)) {
            maybeMigratePlaintextToEncrypted(usersDbPath);
            return;
        }

        List<String> lines = new ArrayList<>();
        lines.add(HEADER);
        lines.add(buildUserRow("demo_user", "user", "UserDemo@1234", "Brooklyn"));
        lines.add(buildUserRow("demo_reviewer", "reviewer", "ReviewDemo@1234", "Brooklyn"));
        writeEncryptedUsers(usersDbPath, lines);
    }

    public static Session authenticate(Path usersDbPath, String username, String password) throws IOException {
        if (username == null || username.isBlank()) {
            throw new ValidationException("username is required");
        }
        if (password == null || password.isBlank()) {
            throw new ValidationException("password is required");
        }

        List<String> lines = readUsersLines(usersDbPath);
        if (lines.isEmpty()) {
            throw new ValidationException("users DB is empty");
        }

        boolean changed = false;
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.isEmpty()) {
                continue;
            }
            AccountRecord acc = parseAccount(line);
            if (acc == null || !acc.username.equals(username)) {
                continue;
            }

            if (!"active".equals(acc.status)) {
                AuditService.log("auth.login", username, "users", "denied", "account not active");
                throw new ValidationException("account is not active");
            }
            if (!acc.role.equals("user") && !acc.role.equals("reviewer")) {
                AuditService.log("auth.login", username, "users", "denied", "invalid role");
                throw new ValidationException("account role is invalid");
            }
            if (isLocked(acc.lockedUntil)) {
                AuditService.log("auth.login", username, "users", "denied", "account locked");
                throw new ValidationException("account locked. Try later.");
            }

            byte[] salt = Base64.getDecoder().decode(acc.saltB64);
            if (!verifyPassword(password, salt, acc.passwordHash)) {
                acc.failedAttempts += 1;
                if (acc.failedAttempts >= maxFailedAttempts()) {
                    acc.lockedUntil = Instant.now().plus(lockoutMinutes(), ChronoUnit.MINUTES).toString();
                    acc.failedAttempts = 0;
                }
                lines.set(i, acc.toCsv());
                writeEncryptedUsers(usersDbPath, lines);
                AuditService.log("auth.login", username, "users", "failed", "invalid password");
                throw new ValidationException("invalid username or password");
            }

            if (acc.failedAttempts != 0 || (acc.lockedUntil != null && !acc.lockedUntil.isBlank())) {
                acc.failedAttempts = 0;
                acc.lockedUntil = "";
                changed = true;
            }
            if (isLegacyHash(acc.passwordHash)) {
                acc.passwordHash = encodePbkdf2Hash(password, salt);
                changed = true;
            }

            if (changed) {
                lines.set(i, acc.toCsv());
                writeEncryptedUsers(usersDbPath, lines);
            }
            AuditService.log("auth.login", username, "users", "success", "role=" + acc.role);
            return new Session(acc.username, acc.role, acc.defaultLocation);
        }

        AuditService.log("auth.login", username, "users", "failed", "unknown username");
        throw new ValidationException("invalid username or password");
    }

    public static void createAccount(Path usersDbPath, String username, String role, String password, String defaultLocation) throws IOException {
        validateNewAccount(username, role, password, defaultLocation);

        ensureDefaultUsers(usersDbPath);
        List<String> lines = readUsersLines(usersDbPath);
        for (int i = 1; i < lines.size(); i++) {
            AccountRecord acc = parseAccount(lines.get(i));
            if (acc != null && acc.username.equals(username)) {
                throw new ValidationException("username already exists");
            }
        }

        lines.add(buildUserRow(username, role, password, defaultLocation));
        writeEncryptedUsers(usersDbPath, lines);
        AuditService.log("auth.create_account", username, "users", "success", "role=" + role + ",location=" + defaultLocation);
    }

    private static void validateNewAccount(String username, String role, String password, String defaultLocation) {
        if (username == null || username.isBlank()) {
            throw new ValidationException("username is required");
        }
        if (!username.matches("[a-zA-Z0-9._-]{3,40}")) {
            throw new ValidationException("username must be 3-40 chars and contain only letters, numbers, ., _, -");
        }
        if (!"user".equals(role) && !"reviewer".equals(role)) {
            throw new ValidationException("role must be user or reviewer");
        }
        if (password == null || password.length() < 12) {
            throw new ValidationException("password must be at least 12 characters");
        }
        if (!password.matches(".*[A-Z].*")) {
            throw new ValidationException("password must include at least one uppercase letter");
        }
        if (!password.matches(".*[a-z].*")) {
            throw new ValidationException("password must include at least one lowercase letter");
        }
        if (!password.matches(".*[0-9].*")) {
            throw new ValidationException("password must include at least one number");
        }
        if (!password.matches(".*[^A-Za-z0-9].*")) {
            throw new ValidationException("password must include at least one special character");
        }
        if (defaultLocation == null || defaultLocation.isBlank()) {
            throw new ValidationException("default location is required");
        }
        if (defaultLocation.length() > 80) {
            throw new ValidationException("default location must be <= 80 characters");
        }
    }

    private static boolean isLocked(String lockedUntil) {
        if (lockedUntil == null || lockedUntil.isBlank()) {
            return false;
        }
        try {
            return Instant.parse(lockedUntil).isAfter(Instant.now());
        } catch (Exception ex) {
            return false;
        }
    }

    private static int maxFailedAttempts() {
        return parseInt(System.getProperty("auth.max.failed", System.getenv().getOrDefault("AUTH_MAX_FAILED_ATTEMPTS", "5")), 5);
    }

    private static int lockoutMinutes() {
        return parseInt(System.getProperty("auth.lockout.minutes", System.getenv().getOrDefault("AUTH_LOCKOUT_MINUTES", "15")), 15);
    }

    private static int parseInt(String raw, int fallback) {
        try {
            return Integer.parseInt(raw);
        } catch (Exception ex) {
            return fallback;
        }
    }

    private static void maybeMigratePlaintextToEncrypted(Path usersDbPath) throws IOException {
        byte[] raw = Files.readAllBytes(usersDbPath);
        String text = new String(raw, StandardCharsets.UTF_8);
        if (text.startsWith(ENC_PREFIX_V1 + ":") || text.startsWith(ENC_PREFIX_V2 + ":")) {
            return;
        }
        List<String> lines = Files.readAllLines(usersDbPath, StandardCharsets.UTF_8);
        if (lines.isEmpty()) {
            throw new ValidationException("users DB format invalid");
        }
        if (!lines.get(0).startsWith("username,role,salt_b64,password_hash_b64,status")) {
            throw new ValidationException("users DB format invalid");
        }
        normalizeHeaderAndRows(lines);
        writeEncryptedUsers(usersDbPath, lines);
    }

    private static List<String> readUsersLines(Path usersDbPath) throws IOException {
        if (!Files.exists(usersDbPath)) {
            throw new ValidationException("users DB not found: " + usersDbPath);
        }
        byte[] raw = Files.readAllBytes(usersDbPath);
        String text = new String(raw, StandardCharsets.UTF_8);
        List<String> lines;

        if (text.startsWith(ENC_PREFIX_V2 + ":") || text.startsWith(ENC_PREFIX_V1 + ":")) {
            String decrypted = decryptEnvelope(text);
            lines = splitLines(decrypted);
        } else {
            lines = Files.readAllLines(usersDbPath, StandardCharsets.UTF_8);
            normalizeHeaderAndRows(lines);
            writeEncryptedUsers(usersDbPath, lines);
            return lines;
        }

        normalizeHeaderAndRows(lines);
        return lines;
    }

    private static void normalizeHeaderAndRows(List<String> lines) {
        if (lines.isEmpty()) {
            return;
        }
        lines.set(0, HEADER);
        for (int i = 1; i < lines.size(); i++) {
            AccountRecord acc = parseAccount(lines.get(i));
            if (acc == null) {
                continue;
            }
            lines.set(i, acc.toCsv());
        }
    }

    private static void writeEncryptedUsers(Path usersDbPath, List<String> lines) throws IOException {
        Files.createDirectories(usersDbPath.getParent());
        String plaintext = String.join("\n", lines);
        String envelope = encryptEnvelope(plaintext);
        Files.writeString(usersDbPath, envelope, StandardCharsets.UTF_8);
        IntegrityService.writeSignature(usersDbPath);
    }

    private static String encryptEnvelope(String plaintext) {
        try {
            KeyService.KeyRef active = KeyService.activeUsersKey();
            byte[] iv = randomBytes(12);
            byte[] salt = randomBytes(16);
            SecretKey key = deriveKey(active.key, salt);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            return ENC_PREFIX_V2 + ":"
                + active.version + ":"
                + Base64.getEncoder().encodeToString(iv) + ":"
                + Base64.getEncoder().encodeToString(salt) + ":"
                + Base64.getEncoder().encodeToString(ct);
        } catch (ValidationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new RuntimeException("users DB encryption failed", ex);
        }
    }

    private static String decryptEnvelope(String envelope) {
        if (envelope.startsWith(ENC_PREFIX_V2 + ":")) {
            return decryptV2(envelope);
        }
        if (envelope.startsWith(ENC_PREFIX_V1 + ":")) {
            return decryptLegacyV1(envelope);
        }
        throw new ValidationException("users DB encrypted format invalid");
    }

    private static String decryptV2(String envelope) {
        try {
            String[] parts = envelope.split(":", 5);
            if (parts.length != 5) {
                throw new ValidationException("users DB encrypted format invalid");
            }
            String version = parts[1];
            Map<String, String> keys = KeyService.allUsersKeys();
            String keyValue = keys.get(version);
            if (keyValue == null) {
                throw new ValidationException("missing users key version: " + version);
            }

            byte[] iv = Base64.getDecoder().decode(parts[2]);
            byte[] salt = Base64.getDecoder().decode(parts[3]);
            byte[] ct = Base64.getDecoder().decode(parts[4]);
            SecretKey key = deriveKey(keyValue, salt);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] pt = cipher.doFinal(ct);
            return new String(pt, StandardCharsets.UTF_8);
        } catch (ValidationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new ValidationException("unable to decrypt users DB (check key ring)");
        }
    }

    private static String decryptLegacyV1(String envelope) {
        String[] parts = envelope.split(":", 4);
        if (parts.length != 4) {
            throw new ValidationException("users DB encrypted format invalid");
        }
        byte[] iv = Base64.getDecoder().decode(parts[1]);
        byte[] salt = Base64.getDecoder().decode(parts[2]);
        byte[] ct = Base64.getDecoder().decode(parts[3]);

        for (String keyValue : KeyService.allUsersKeys().values()) {
            try {
                SecretKey key = deriveKey(keyValue, salt);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
                byte[] pt = cipher.doFinal(ct);
                return new String(pt, StandardCharsets.UTF_8);
            } catch (Exception ignored) {
            }
        }
        throw new ValidationException("unable to decrypt legacy users DB (check key ring)");
    }

    private static SecretKey deriveKey(String passphrase, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, 65536, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static List<String> splitLines(String text) {
        String[] arr = text.split("\\R", -1);
        List<String> out = new ArrayList<>();
        for (String s : arr) {
            if (!s.isEmpty()) {
                out.add(s);
            }
        }
        return out;
    }

    private static String buildUserRow(String username, String role, String password, String defaultLocation) {
        byte[] salt = randomBytes(16);
        return String.join(",",
            csv(username),
            csv(role),
            csv(Base64.getEncoder().encodeToString(salt)),
            csv(encodePbkdf2Hash(password, salt)),
            csv("active"),
            csv("0"),
            csv(""),
            csv(defaultLocation)
        );
    }

    private static AccountRecord parseAccount(String line) {
        List<String> cols = parseCsvLine(line);
        if (cols.size() < 5) {
            return null;
        }
        AccountRecord acc = new AccountRecord();
        acc.username = cols.get(0);
        acc.role = cols.get(1);
        acc.saltB64 = cols.get(2);
        acc.passwordHash = cols.get(3);
        acc.status = cols.get(4);
        acc.failedAttempts = cols.size() > 5 ? parseInt(cols.get(5), 0) : 0;
        acc.lockedUntil = cols.size() > 6 ? cols.get(6) : "";
        acc.defaultLocation = cols.size() > 7 ? cols.get(7) : "";
        if (acc.defaultLocation == null || acc.defaultLocation.isBlank()) {
            acc.defaultLocation = "Brooklyn";
        }
        return acc;
    }

    private static class AccountRecord {
        String username;
        String role;
        String saltB64;
        String passwordHash;
        String status;
        int failedAttempts;
        String lockedUntil;
        String defaultLocation;

        String toCsv() {
            return String.join(",",
                csv(username),
                csv(role),
                csv(saltB64),
                csv(passwordHash),
                csv(status),
                csv(Integer.toString(failedAttempts)),
                csv(lockedUntil == null ? "" : lockedUntil),
                csv(defaultLocation == null ? "" : defaultLocation)
            );
        }
    }

    private static boolean verifyPassword(String password, byte[] salt, String storedHash) {
        if (storedHash == null || storedHash.isBlank()) {
            return false;
        }
        if (storedHash.startsWith(HASH_SCHEME_PBKDF2 + "$")) {
            String[] parts = storedHash.split("\\$", 3);
            if (parts.length != 3) {
                return false;
            }
            int iterations = parseInt(parts[1], -1);
            if (iterations < 1) {
                return false;
            }
            byte[] expected;
            try {
                expected = Base64.getDecoder().decode(parts[2]);
            } catch (IllegalArgumentException ex) {
                return false;
            }
            byte[] actual = hashPasswordPbkdf2(password, salt, iterations, expected.length);
            return MessageDigest.isEqual(expected, actual);
        }

        byte[] expected;
        try {
            expected = Base64.getDecoder().decode(storedHash);
        } catch (IllegalArgumentException ex) {
            return false;
        }
        byte[] actual = hashPasswordLegacySha256(password, salt);
        return MessageDigest.isEqual(expected, actual);
    }

    private static boolean isLegacyHash(String storedHash) {
        return storedHash != null && !storedHash.startsWith(HASH_SCHEME_PBKDF2 + "$");
    }

    private static String encodePbkdf2Hash(String password, byte[] salt) {
        byte[] hash = hashPasswordPbkdf2(password, salt, PASSWORD_HASH_ITERATIONS, PASSWORD_HASH_BYTES);
        return HASH_SCHEME_PBKDF2 + "$" + PASSWORD_HASH_ITERATIONS + "$" + Base64.getEncoder().encodeToString(hash);
    }

    private static byte[] hashPasswordLegacySha256(String password, byte[] salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(salt);
            digest.update(password.getBytes(StandardCharsets.UTF_8));
            return digest.digest();
        } catch (Exception ex) {
            throw new RuntimeException("legacy password hashing failed", ex);
        }
    }

    private static byte[] hashPasswordPbkdf2(String password, byte[] salt, int iterations, int keyBytes) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyBytes * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return skf.generateSecret(spec).getEncoded();
        } catch (Exception ex) {
            throw new RuntimeException("pbkdf2 password hashing failed", ex);
        }
    }

    private static byte[] randomBytes(int len) {
        byte[] out = new byte[len];
        new SecureRandom().nextBytes(out);
        return out;
    }

    private static String csv(String value) {
        if (value == null) {
            return "";
        }
        if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }

    private static List<String> parseCsvLine(String line) {
        List<String> result = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;

        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                if (inQuotes && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    current.append('"');
                    i++;
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (c == ',' && !inQuotes) {
                result.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        result.add(current.toString());
        return result;
    }
}
