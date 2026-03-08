package com.communityguardian.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

public class AuditService {
    public static void log(String action, String actor, String target, String outcome, String details) {
        try {
            Path path = auditPath();
            Files.createDirectories(path.getParent());
            String line = "{" +
                "\"ts\":\"" + esc(Instant.now().toString()) + "\"," +
                "\"action\":\"" + esc(action) + "\"," +
                "\"actor\":\"" + esc(actor) + "\"," +
                "\"target\":\"" + esc(target) + "\"," +
                "\"outcome\":\"" + esc(outcome) + "\"," +
                "\"details\":\"" + esc(details) + "\"" +
                "}";
            Files.writeString(path, line + "\n", StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.APPEND);
        } catch (IOException ignored) {
            // Do not fail user flows because of audit sink issues in this prototype.
        }
    }

    private static Path auditPath() {
        String p = System.getProperty("audit.log.path");
        if (p != null && !p.isBlank()) {
            return Path.of(p);
        }
        String e = System.getenv("AUDIT_LOG_PATH");
        if (e != null && !e.isBlank()) {
            return Path.of(e);
        }
        return Path.of("data", "audit.log");
    }

    private static String esc(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
