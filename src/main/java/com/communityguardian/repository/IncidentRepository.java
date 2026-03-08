package com.communityguardian.repository;

import com.communityguardian.exception.ValidationException;
import com.communityguardian.model.Incident;
import com.communityguardian.service.AuditService;
import com.communityguardian.service.CategorizationService;
import com.communityguardian.service.ConfidenceService;
import com.communityguardian.service.IntegrityService;
import com.communityguardian.service.KeyService;
import com.communityguardian.validation.Validator;

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
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Collectors;

public class IncidentRepository {
    private static final String HEADER = "id,title,category,severity,location,details,verified,status,source_type,corroboration_count,confidence_score,needs_review,expires_at,reported_at,cluster_id";
    private static final String LOCATION_ENC_PREFIX_V1 = "ENCLOCv1";
    private static final String LOCATION_ENC_PREFIX_V2 = "ENCLOCv2";

    public static class ListOptions {
        public String keyword;
        public String category;
        public String severity;
        public String status;
        public String location;
        public boolean verifiedOnly;
        public boolean needsReviewOnly;
        public boolean includeExpired;
        public Double minConfidence;
    }

    public static void initDb(Path samplePath, Path dbPath) throws IOException {
        Files.createDirectories(dbPath.getParent());
        Files.writeString(dbPath, Files.readString(samplePath, StandardCharsets.UTF_8), StandardCharsets.UTF_8);
        IntegrityService.writeSignature(dbPath);
    }

    public static List<Incident> load(Path dbPath) throws IOException {
        if (!Files.exists(dbPath)) {
            throw new ValidationException("Data file not found: " + dbPath);
        }
        IntegrityService.verifyIfPresent(dbPath);

        List<String> lines = Files.readAllLines(dbPath, StandardCharsets.UTF_8);
        if (lines.isEmpty()) {
            throw new ValidationException("CSV data is empty");
        }

        List<Incident> incidents = new ArrayList<>();
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.isEmpty()) {
                continue;
            }
            List<String> cols = parseCsvLine(line);
            if (cols.size() != 9 && cols.size() != 15) {
                throw new ValidationException("Invalid CSV row at line " + (i + 1));
            }
            Incident in = parseIncident(cols);
            incidents.add(in);
        }
        return incidents;
    }

    public static void save(Path dbPath, List<Incident> incidents) throws IOException {
        List<String> lines = new ArrayList<>();
        lines.add(HEADER);
        for (Incident in : incidents) {
            lines.add(String.join(",",
                csv(in.id),
                csv(in.title),
                csv(in.category),
                csv(in.severity),
                csv(encryptLocation(in.location)),
                csv(in.details),
                csv(Boolean.toString(in.verified)),
                csv(in.status),
                csv(in.sourceType),
                csv(Integer.toString(in.corroborationCount)),
                csv(String.format(Locale.US, "%.4f", in.confidenceScore)),
                csv(Boolean.toString(in.needsReview)),
                csv(in.expiresAt),
                csv(in.reportedAt),
                csv(in.clusterId)
            ));
        }
        Files.createDirectories(dbPath.getParent());
        Files.write(dbPath, lines, StandardCharsets.UTF_8);
        IntegrityService.writeSignature(dbPath);
    }

    public static Incident create(
        Path dbPath,
        String title,
        String category,
        String severity,
        String location,
        String details,
        boolean verified,
        String sourceType,
        int corroborationCount,
        int expiresDays,
        boolean aiAdjust
    ) throws IOException {
        String resolvedCategory = CategorizationService.resolveCategory(category, title, details);
        Validator.validateCreateInput(title, resolvedCategory, severity, location, details, sourceType, corroborationCount);
        if (expiresDays < 1) {
            throw new ValidationException("expires-days must be >= 1");
        }

        List<Incident> incidents = load(dbPath);
        Incident in = new Incident();
        in.id = UUID.randomUUID().toString();
        in.title = title.trim();
        in.category = resolvedCategory;
        in.severity = severity;
        in.location = location.trim();
        in.details = details.trim();
        in.verified = verified;
        in.status = "open";
        in.sourceType = sourceType;
        in.reportedAt = Instant.now().toString();
        in.expiresAt = OffsetDateTime.now(ZoneOffset.UTC).plusDays(expiresDays).truncatedTo(ChronoUnit.SECONDS).toInstant().toString();
        in.clusterId = clusterIdFor(in);
        // Corroboration is system-validated from other matching reports, not trusted user input.
        in.corroborationCount = computeValidatedCorroboration(incidents, in);

        double rule = ConfidenceService.computeRuleScore(in);
        Double aiScore = ConfidenceService.tryAiScore(in, aiAdjust);
        in.confidenceScore = ConfidenceService.mergeRuleAndAi(rule, aiScore);
        boolean contradictionGate = ConfidenceService.isContradictionGateTriggered(in, aiScore);
        in.needsReview = ConfidenceService.shouldFlagForReview(in, aiScore);

        incidents.add(in);
        save(dbPath, incidents);
        String meta = "category=" + in.category + ",severity=" + in.severity + ",contradictionGate=" + contradictionGate;
        AuditService.log("incident.create", "system", in.id, "success", meta);
        return in;
    }

    public static List<Incident> list(Path dbPath, ListOptions options) throws IOException {
        Validator.validateStatus(options.status);
        if (options.category != null && !options.category.isBlank() && !Validator.ALLOWED_CATEGORIES.contains(options.category)) {
            throw new ValidationException("category must be one of " + Validator.ALLOWED_CATEGORIES);
        }
        if (options.severity != null && !options.severity.isBlank() && !Validator.ALLOWED_SEVERITIES.contains(options.severity)) {
            throw new ValidationException("severity must be one of " + Validator.ALLOWED_SEVERITIES);
        }
        if (options.minConfidence != null && (options.minConfidence < 0.0 || options.minConfidence > 1.0)) {
            throw new ValidationException("min-confidence must be between 0.0 and 1.0");
        }

        List<Incident> incidents = load(dbPath);
        return incidents.stream().filter(in -> {
            if (!options.includeExpired && isExpired(in)) {
                return false;
            }
            if (options.keyword != null && !options.keyword.isBlank()) {
                String q = options.keyword.toLowerCase();
                if (!in.title.toLowerCase().contains(q) && !in.details.toLowerCase().contains(q)) {
                    return false;
                }
            }
            if (options.location != null && !options.location.isBlank() && !in.location.equalsIgnoreCase(options.location)) {
                return false;
            }
            if (options.category != null && !options.category.isBlank() && !in.category.equals(options.category)) {
                return false;
            }
            if (options.severity != null && !options.severity.isBlank() && !in.severity.equals(options.severity)) {
                return false;
            }
            if (options.status != null && !options.status.isBlank() && !in.status.equals(options.status)) {
                return false;
            }
            if (options.verifiedOnly && !in.verified) {
                return false;
            }
            if (options.needsReviewOnly && !in.needsReview) {
                return false;
            }
            if (options.minConfidence != null && in.confidenceScore < options.minConfidence) {
                return false;
            }
            return true;
        }).collect(Collectors.toList());
    }

    public static Incident update(Path dbPath, String id, String status, Boolean verified, Integer corroborationCount) throws IOException {
        Validator.validateStatus(status);
        if (corroborationCount != null && corroborationCount < 0) {
            throw new ValidationException("corroboration-count must be >= 0");
        }

        List<Incident> incidents = load(dbPath);
        Optional<Incident> found = incidents.stream().filter(in -> in.id.equals(id)).findFirst();
        if (found.isEmpty()) {
            throw new ValidationException("incident not found: " + id);
        }

        Incident in = found.get();
        if (status != null) {
            in.status = status;
        }
        if (verified != null) {
            in.verified = verified;
        }
        // Corroboration is system-validated from cluster evidence. Manual value is ignored for scoring.

        in.clusterId = clusterIdFor(in);
        in.corroborationCount = computeValidatedCorroboration(incidents, in);
        double rule = ConfidenceService.computeRuleScore(in);
        in.confidenceScore = rule;
        in.needsReview = ConfidenceService.shouldFlagForReview(in);

        save(dbPath, incidents);
        AuditService.log("incident.update", "system", in.id, "success", "status=" + in.status + ",verified=" + in.verified);
        return in;
    }

    public static Incident findById(Path dbPath, String id) throws IOException {
        List<Incident> incidents = load(dbPath);
        return incidents.stream()
            .filter(in -> in.id.equals(id))
            .findFirst()
            .orElseThrow(() -> new ValidationException("incident not found: " + id));
    }

    public static int pruneExpired(Path dbPath) throws IOException {
        List<Incident> incidents = load(dbPath);
        List<Incident> kept = incidents.stream().filter(in -> !isExpired(in)).collect(Collectors.toList());
        save(dbPath, kept);
        return incidents.size() - kept.size();
    }

    public static List<Incident> collapseByCluster(List<Incident> incidents) {
        return incidents.stream()
            .collect(Collectors.groupingBy(in -> in.clusterId))
            .values()
            .stream()
            .flatMap(group -> selectRepresentative(group).stream())
            .collect(Collectors.toList());
    }

    private static Optional<Incident> selectRepresentative(List<Incident> group) {
        return group.stream().max((a, b) -> {
            int byVerified = Boolean.compare(a.verified, b.verified);
            if (byVerified != 0) {
                return byVerified;
            }
            int byConfidence = Double.compare(a.confidenceScore, b.confidenceScore);
            if (byConfidence != 0) {
                return byConfidence;
            }
            return a.reportedAt.compareTo(b.reportedAt);
        });
    }

    public static String clusterIdFor(Incident in) {
        String normalized = (in.title == null ? "" : in.title.toLowerCase())
            .replaceAll("[^a-z0-9 ]", " ")
            .replaceAll("\\s+", " ")
            .trim();
        String[] tokens = normalized.split(" ");
        StringBuilder key = new StringBuilder();
        int used = 0;
        for (String token : tokens) {
            if (token.isBlank()) {
                continue;
            }
            if (isStopWord(token)) {
                continue;
            }
            if (used > 0) {
                key.append("-");
            }
            key.append(token);
            used++;
            if (used == 4) {
                break;
            }
        }
        String stem = key.length() == 0 ? normalized : key.toString();
        return in.category + "|" + in.location.toLowerCase() + "|" + stem;
    }

    public static boolean isExpired(Incident in) {
        if (in.expiresAt == null || in.expiresAt.isBlank()) {
            return false;
        }
        try {
            return Instant.parse(in.expiresAt).isBefore(Instant.now());
        } catch (Exception ex) {
            return false;
        }
    }

    private static Incident parseIncident(List<String> cols) {
        Incident in = new Incident();
        in.id = cols.get(0);
        in.title = cols.get(1);
        in.category = cols.get(2);
        in.severity = cols.get(3);
        in.location = decryptLocationIfNeeded(cols.get(4));
        in.details = cols.get(5);
        in.verified = Boolean.parseBoolean(cols.get(6));
        in.status = cols.get(7);

        if (cols.size() == 15) {
            in.sourceType = blankToDefault(cols.get(8), "community");
            in.corroborationCount = parseIntOrDefault(cols.get(9), 1);
            in.confidenceScore = parseDoubleOrDefault(cols.get(10), 0.5);
            in.needsReview = Boolean.parseBoolean(cols.get(11));
            in.expiresAt = cols.get(12);
            in.reportedAt = cols.get(13);
            in.clusterId = blankToDefault(cols.get(14), clusterIdFor(in));
        } else {
            in.sourceType = "community";
            in.corroborationCount = 1;
            in.reportedAt = cols.get(8);
            in.expiresAt = "";
            in.clusterId = clusterIdFor(in);
            in.confidenceScore = ConfidenceService.computeRuleScore(in);
            in.needsReview = ConfidenceService.shouldFlagForReview(in);
        }
        return in;
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

    private static int parseIntOrDefault(String raw, int fallback) {
        try {
            return Integer.parseInt(raw);
        } catch (Exception ex) {
            return fallback;
        }
    }

    private static double parseDoubleOrDefault(String raw, double fallback) {
        try {
            return Double.parseDouble(raw);
        } catch (Exception ex) {
            return fallback;
        }
    }

    private static String blankToDefault(String raw, String fallback) {
        return (raw == null || raw.isBlank()) ? fallback : raw;
    }

    private static int computeValidatedCorroboration(List<Incident> incidents, Incident target) {
        String cluster = target.clusterId == null || target.clusterId.isBlank() ? clusterIdFor(target) : target.clusterId;
        return (int) incidents.stream()
            .filter(i -> i.id != null && !i.id.equals(target.id))
            .filter(i -> !isExpired(i))
            .filter(i -> {
                String candidateCluster = i.clusterId == null || i.clusterId.isBlank() ? clusterIdFor(i) : i.clusterId;
                return candidateCluster.equals(cluster);
            })
            .map(i -> i.id)
            .distinct()
            .count();
    }

    private static String encryptLocation(String plainLocation) {
        if (plainLocation == null || plainLocation.isBlank()) {
            return "";
        }
        try {
            KeyService.KeyRef active = KeyService.activeIncidentKey();
            byte[] iv = randomBytes(12);
            byte[] salt = randomBytes(16);
            SecretKey key = deriveKey(active.key, salt);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] ct = cipher.doFinal(plainLocation.getBytes(StandardCharsets.UTF_8));

            return LOCATION_ENC_PREFIX_V2 + ":"
                + active.version + ":"
                + Base64.getEncoder().encodeToString(iv) + ":"
                + Base64.getEncoder().encodeToString(salt) + ":"
                + Base64.getEncoder().encodeToString(ct);
        } catch (ValidationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new RuntimeException("location encryption failed", ex);
        }
    }

    private static String decryptLocationIfNeeded(String rawLocation) {
        if (rawLocation == null || rawLocation.isBlank()) {
            return "";
        }
        if (!rawLocation.startsWith(LOCATION_ENC_PREFIX_V1 + ":") && !rawLocation.startsWith(LOCATION_ENC_PREFIX_V2 + ":")) {
            return rawLocation;
        }
        if (rawLocation.startsWith(LOCATION_ENC_PREFIX_V2 + ":")) {
            try {
                String[] parts = rawLocation.split(":", 5);
                if (parts.length != 5) {
                    throw new ValidationException("invalid encrypted location format");
                }
                String version = parts[1];
                Map<String, String> keys = KeyService.allIncidentKeys();
                String keyValue = keys.get(version);
                if (keyValue == null) {
                    throw new ValidationException("missing incident data key version: " + version);
                }
                byte[] iv = Base64.getDecoder().decode(parts[2]);
                byte[] salt = Base64.getDecoder().decode(parts[3]);
                byte[] ct = Base64.getDecoder().decode(parts[4]);
                return decryptWithKey(ct, keyValue, iv, salt);
            } catch (ValidationException ex) {
                throw ex;
            } catch (Exception ex) {
                throw new ValidationException("unable to decrypt incident location (check INCIDENT_DATA_KEYS)");
            }
        }

        // Legacy ENCLOCv1 format (no key version): try all keys.
        String[] legacy = rawLocation.split(":", 4);
        if (legacy.length != 4) {
            throw new ValidationException("invalid encrypted location format");
        }
        byte[] iv = Base64.getDecoder().decode(legacy[1]);
        byte[] salt = Base64.getDecoder().decode(legacy[2]);
        byte[] ct = Base64.getDecoder().decode(legacy[3]);
        for (String keyValue : KeyService.allIncidentKeys().values()) {
            try {
                return decryptWithKey(ct, keyValue, iv, salt);
            } catch (Exception ignored) {
            }
        }
        throw new ValidationException("unable to decrypt incident location (check INCIDENT_DATA_KEYS)");
    }

    private static String decryptWithKey(byte[] ct, String keyValue, byte[] iv, byte[] salt) throws Exception {
        SecretKey key = deriveKey(keyValue, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] pt = cipher.doFinal(ct);
        return new String(pt, StandardCharsets.UTF_8);
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

    private static boolean isStopWord(String token) {
        return token.equals("the")
            || token.equals("a")
            || token.equals("an")
            || token.equals("at")
            || token.equals("near")
            || token.equals("about")
            || token.equals("same")
            || token.equals("of")
            || token.equals("to")
            || token.equals("and")
            || token.equals("for");
    }
}
