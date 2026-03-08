package com.communityguardian.service;

import com.communityguardian.exception.ValidationException;

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
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class SafeCircleService {
    private static final String STATUS_HEADER = "circle,sender,created_at,iv_b64,salt_b64,ciphertext_b64";
    private static final String MEMBERS_HEADER = "circle,member,added_at,added_by,status,can_manage,is_owner";

    public static class StatusUpdate {
        public String circle;
        public String sender;
        public String createdAt;
        public String message;
    }

    public static class MemberEntry {
        public String circle;
        public String member;
        public String addedAt;
        public String addedBy;
        public String status;
        public boolean canManage;
        public boolean isOwner;
    }

    public static void createCircle(Path membersDbPath, String circle, String owner) throws IOException {
        validateCircleAndUser(circle, owner, "owner");
        List<String> lines = readOrInitMembers(membersDbPath);

        boolean exists = lines.stream().skip(1).map(SafeCircleService::parseMember)
            .anyMatch(m -> m != null && m.circle.equals(circle) && "active".equals(m.status));
        if (exists) {
            throw new ValidationException("circle already exists: " + circle);
        }

        lines.add(memberRow(circle, owner, Instant.now().toString(), owner, "active", true, true));
        writeLines(membersDbPath, lines);
        AuditService.log("circle.create", owner, circle, "success", "owner created circle");
    }

    public static void addMember(Path membersDbPath, String circle, String actor, String member) throws IOException {
        validateCircleAndUser(circle, actor, "actor");
        validateCircleAndUser(circle, member, "member");
        requireManageAccess(membersDbPath, circle, actor);

        List<String> lines = readOrInitMembers(membersDbPath);
        boolean alreadyActive = lines.stream().skip(1).map(SafeCircleService::parseMember)
            .anyMatch(m -> m != null && m.circle.equals(circle) && m.member.equals(member) && "active".equals(m.status));
        if (alreadyActive) {
            throw new ValidationException("member already active in circle");
        }

        lines.add(memberRow(circle, member, Instant.now().toString(), actor, "active", false, false));
        writeLines(membersDbPath, lines);
        AuditService.log("circle.member.add", actor, circle, "success", "member=" + member);
    }

    public static void removeMember(Path membersDbPath, String circle, String actor, String member) throws IOException {
        validateCircleAndUser(circle, actor, "actor");
        validateCircleAndUser(circle, member, "member");
        requireManageAccess(membersDbPath, circle, actor);

        List<String> lines = readOrInitMembers(membersDbPath);
        boolean changed = false;

        for (int i = 1; i < lines.size(); i++) {
            MemberEntry m = parseMember(lines.get(i));
            if (m == null || !m.circle.equals(circle) || !m.member.equals(member) || !"active".equals(m.status)) {
                continue;
            }
            if (m.isOwner) {
                throw new ValidationException("owner cannot be removed from circle");
            }
            lines.set(i, memberRow(m.circle, m.member, m.addedAt, m.addedBy, "inactive", m.canManage, m.isOwner));
            changed = true;
            break;
        }

        if (!changed) {
            throw new ValidationException("active member not found in circle");
        }
        writeLines(membersDbPath, lines);
        AuditService.log("circle.member.remove", actor, circle, "success", "member=" + member);
    }

    public static void setManageAccess(Path membersDbPath, String circle, String ownerActor, String member, boolean canManage) throws IOException {
        validateCircleAndUser(circle, ownerActor, "owner actor");
        validateCircleAndUser(circle, member, "member");
        requireOwner(membersDbPath, circle, ownerActor);

        List<String> lines = readOrInitMembers(membersDbPath);
        boolean changed = false;
        for (int i = 1; i < lines.size(); i++) {
            MemberEntry m = parseMember(lines.get(i));
            if (m == null || !m.circle.equals(circle) || !m.member.equals(member) || !"active".equals(m.status)) {
                continue;
            }
            if (m.isOwner && !canManage) {
                throw new ValidationException("owner must retain manage access");
            }
            lines.set(i, memberRow(m.circle, m.member, m.addedAt, m.addedBy, m.status, canManage, m.isOwner));
            changed = true;
            break;
        }

        if (!changed) {
            throw new ValidationException("active member not found in circle");
        }
        writeLines(membersDbPath, lines);
        AuditService.log("circle.member.access", ownerActor, circle, "success", "member=" + member + ",canManage=" + canManage);
    }

    public static List<MemberEntry> listMembers(Path membersDbPath, String circle, String actor) throws IOException {
        validateCircleAndUser(circle, actor, "actor");
        ensureMember(membersDbPath, circle, actor);

        List<String> lines = readOrInitMembers(membersDbPath);
        List<MemberEntry> out = new ArrayList<>();
        for (int i = 1; i < lines.size(); i++) {
            MemberEntry m = parseMember(lines.get(i));
            if (m == null || !m.circle.equals(circle) || !"active".equals(m.status)) {
                continue;
            }
            out.add(m);
        }
        return out;
    }

    public static StatusUpdate shareStatus(Path dbPath, Path membersDbPath, String circle, String actor, String sender, String message, String passphrase) throws IOException {
        validateCircleAndUser(circle, actor, "actor");
        validateCircleAndUser(circle, sender, "sender");
        ensureMember(membersDbPath, circle, actor);
        if (!actor.equals(sender)) {
            throw new ValidationException("actor must match sender for status sharing");
        }
        if (message == null || message.isBlank()) {
            throw new ValidationException("message is required");
        }
        if (passphrase == null || passphrase.length() < 8) {
            throw new ValidationException("passphrase must be at least 8 characters");
        }

        byte[] iv = randomBytes(12);
        byte[] salt = randomBytes(16);
        String cipherText = encrypt(message, passphrase, iv, salt);

        String row = csv(circle) + "," + csv(sender) + "," + csv(Instant.now().toString()) + "," + csv(b64(iv)) + "," + csv(b64(salt)) + "," + csv(cipherText);

        List<String> lines = new ArrayList<>();
        IntegrityService.verifyIfPresent(dbPath);
        if (Files.exists(dbPath)) {
            lines.addAll(Files.readAllLines(dbPath, StandardCharsets.UTF_8));
        }
        if (lines.isEmpty()) {
            lines.add(STATUS_HEADER);
        }
        lines.add(row);
        writeLines(dbPath, lines);
        AuditService.log("circle.status.share", actor, circle, "success", "sender=" + sender);

        StatusUpdate out = new StatusUpdate();
        out.circle = circle;
        out.sender = sender;
        out.createdAt = Instant.now().toString();
        out.message = message;
        return out;
    }

    public static List<StatusUpdate> viewStatus(Path dbPath, Path membersDbPath, String circle, String actor, String passphrase) throws IOException {
        validateCircleAndUser(circle, actor, "actor");
        ensureMember(membersDbPath, circle, actor);

        if (!Files.exists(dbPath)) {
            return List.of();
        }
        IntegrityService.verifyIfPresent(dbPath);
        if (passphrase == null || passphrase.length() < 8) {
            throw new ValidationException("passphrase must be at least 8 characters");
        }

        List<String> lines = Files.readAllLines(dbPath, StandardCharsets.UTF_8);
        if (lines.isEmpty()) {
            return List.of();
        }

        List<StatusUpdate> out = new ArrayList<>();
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.isEmpty()) {
                continue;
            }
            List<String> cols = parseCsvLine(line);
            if (cols.size() != 6) {
                continue;
            }
            if (!cols.get(0).equals(circle)) {
                continue;
            }
            try {
                String msg = decrypt(cols.get(5), passphrase, b64d(cols.get(3)), b64d(cols.get(4)));
                StatusUpdate su = new StatusUpdate();
                su.circle = cols.get(0);
                su.sender = cols.get(1);
                su.createdAt = cols.get(2);
                su.message = msg;
                out.add(su);
            } catch (Exception ex) {
                throw new ValidationException("Unable to decrypt safe-circle messages. Check passphrase.");
            }
        }
        AuditService.log("circle.status.view", actor, circle, "success", "count=" + out.size());
        return out;
    }

    private static void ensureMember(Path membersDbPath, String circle, String actor) throws IOException {
        List<String> lines = readOrInitMembers(membersDbPath);
        boolean isActive = lines.stream().skip(1).map(SafeCircleService::parseMember)
            .anyMatch(m -> m != null && m.circle.equals(circle) && m.member.equals(actor) && "active".equals(m.status));
        if (!isActive) {
            throw new ValidationException("access denied: actor is not an active member of circle");
        }
    }

    private static void requireManageAccess(Path membersDbPath, String circle, String actor) throws IOException {
        MemberEntry actorEntry = findActiveMember(membersDbPath, circle, actor);
        if (!AuthorizationService.canManageMembers(actorEntry)) {
            throw new ValidationException("access denied: actor does not have member-management permission");
        }
    }

    private static void requireOwner(Path membersDbPath, String circle, String ownerActor) throws IOException {
        MemberEntry actorEntry = findActiveMember(membersDbPath, circle, ownerActor);
        if (!AuthorizationService.canChangeManageAccess(actorEntry)) {
            throw new ValidationException("access denied: only circle owner can change management permissions");
        }
    }

    private static MemberEntry findActiveMember(Path membersDbPath, String circle, String member) throws IOException {
        List<String> lines = readOrInitMembers(membersDbPath);
        for (int i = 1; i < lines.size(); i++) {
            MemberEntry m = parseMember(lines.get(i));
            if (m == null) {
                continue;
            }
            if (!m.circle.equals(circle) || !m.member.equals(member) || !"active".equals(m.status)) {
                continue;
            }
            return m;
        }
        return null;
    }

    private static List<String> readOrInitMembers(Path membersDbPath) throws IOException {
        IntegrityService.verifyIfPresent(membersDbPath);
        List<String> lines = new ArrayList<>();
        if (Files.exists(membersDbPath)) {
            lines.addAll(Files.readAllLines(membersDbPath, StandardCharsets.UTF_8));
        }
        if (lines.isEmpty()) {
            lines.add(MEMBERS_HEADER);
            writeLines(membersDbPath, lines);
        }
        return lines;
    }

    private static void validateCircleAndUser(String circle, String user, String userLabel) {
        if (circle == null || circle.isBlank()) {
            throw new ValidationException("circle is required");
        }
        if (user == null || user.isBlank()) {
            throw new ValidationException(userLabel + " is required");
        }
    }

    private static String memberRow(String circle, String member, String addedAt, String addedBy, String status, boolean canManage, boolean isOwner) {
        return csv(circle) + "," + csv(member) + "," + csv(addedAt) + "," + csv(addedBy) + "," + csv(status) + "," + csv(Boolean.toString(canManage)) + "," + csv(Boolean.toString(isOwner));
    }

    private static MemberEntry parseMember(String line) {
        List<String> cols = parseCsvLine(line);
        if (cols.size() != 7 && cols.size() != 5) {
            return null;
        }
        MemberEntry m = new MemberEntry();
        m.circle = cols.get(0);
        m.member = cols.get(1);
        m.addedAt = cols.get(2);
        m.addedBy = cols.get(3);
        m.status = cols.get(4);
        if (cols.size() == 7) {
            m.canManage = Boolean.parseBoolean(cols.get(5));
            m.isOwner = Boolean.parseBoolean(cols.get(6));
        } else {
            // Legacy fallback: no owner/manage flags stored.
            m.canManage = false;
            m.isOwner = false;
        }
        return m;
    }

    private static String encrypt(String plain, String passphrase, byte[] iv, byte[] salt) {
        try {
            SecretKey key = deriveKey(passphrase, salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] encrypted = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            return b64(encrypted);
        } catch (Exception ex) {
            throw new RuntimeException("encryption failed", ex);
        }
    }

    private static String decrypt(String cipherB64, String passphrase, byte[] iv, byte[] salt) {
        try {
            SecretKey key = deriveKey(passphrase, salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] decrypted = cipher.doFinal(b64d(cipherB64));
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception ex) {
            throw new RuntimeException("decryption failed", ex);
        }
    }

    private static SecretKey deriveKey(String passphrase, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, 65536, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static byte[] randomBytes(int len) {
        byte[] out = new byte[len];
        new SecureRandom().nextBytes(out);
        return out;
    }

    private static String b64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static byte[] b64d(String s) {
        return Base64.getDecoder().decode(s);
    }

    private static void writeLines(Path path, List<String> lines) throws IOException {
        Files.createDirectories(path.getParent());
        Files.write(path, lines, StandardCharsets.UTF_8);
        IntegrityService.writeSignature(path);
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
