package com.communityguardian.cli;

import com.communityguardian.auth.AuthService;
import com.communityguardian.exception.ValidationException;
import com.communityguardian.model.Incident;
import com.communityguardian.repository.IncidentRepository;
import com.communityguardian.service.DigestService;
import com.communityguardian.service.IntegrityService;
import com.communityguardian.service.KeyService;
import com.communityguardian.service.ReportInsightsService;
import com.communityguardian.service.SafeCircleService;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class CommunityGuardianApp {
    private static final Path DEFAULT_DB_PATH = Path.of("data", "incidents_db.csv");
    private static final Path DEFAULT_SAMPLE_PATH = Path.of("data", "sample_incidents.csv");
    private static final Path DEFAULT_SAFE_DB_PATH = Path.of("data", "safe_circle_updates.csv");
    private static final Path DEFAULT_CIRCLE_MEMBERS_DB_PATH = Path.of("data", "circle_members.csv");
    private static final Path DEFAULT_USERS_DB_PATH = Path.of("data", "users.csv");

    public static void main(String[] args) {
        try {
            int code = run(args);
            System.exit(code);
        } catch (ValidationException ex) {
            System.err.println("Error: " + ex.getMessage());
            System.exit(2);
        } catch (IOException ex) {
            System.err.println("Error: " + ex.getMessage());
            System.exit(2);
        }
    }

    static int run(String[] args) throws IOException {
        if (args.length == 0) {
            printHelp();
            return 1;
        }

        Map<String, String> opts = parseOptions(args);
        String command = args[0];
        Path db = Path.of(opts.getOrDefault("db", DEFAULT_DB_PATH.toString()));
        String format = opts.getOrDefault("format", "pretty");
        if (!format.equals("pretty") && !format.equals("json")) {
            throw new ValidationException("format must be pretty or json");
        }
        boolean json = format.equals("json");

        return switch (command) {
            case "init-db" -> {
                IncidentRepository.initDb(DEFAULT_SAMPLE_PATH, db);
                if (json) {
                    System.out.println("{\"message\":\"Database initialized\",\"db\":\"" + esc(db.toString()) + "\"}");
                } else {
                    System.out.println(OutputFormatter.formatInitPretty(db.toString()));
                }
                yield 0;
            }
            case "start" -> {
                Path usersDb = Path.of(opts.getOrDefault("users-db", DEFAULT_USERS_DB_PATH.toString()));
                Path safeDb = Path.of(opts.getOrDefault("safe-db", DEFAULT_SAFE_DB_PATH.toString()));
                Path membersDb = Path.of(opts.getOrDefault("members-db", DEFAULT_CIRCLE_MEMBERS_DB_PATH.toString()));
                TerminalWorkbench.start(db, usersDb, safeDb, membersDb);
                yield 0;
            }
            case "create-account" -> {
                Path usersDb = Path.of(opts.getOrDefault("users-db", DEFAULT_USERS_DB_PATH.toString()));
                AuthService.createAccount(
                    usersDb,
                    required(opts, "username"),
                    required(opts, "role"),
                    required(opts, "password"),
                    required(opts, "location")
                );
                if (json) {
                    System.out.println("{\"message\":\"account created\",\"username\":\"" + esc(required(opts, "username")) + "\"}");
                } else {
                    System.out.println("Account created for username: " + required(opts, "username"));
                }
                yield 0;
            }
            case "init-users" -> {
                Path usersDb = Path.of(opts.getOrDefault("users-db", DEFAULT_USERS_DB_PATH.toString()));
                AuthService.ensureDefaultUsers(usersDb);
                IntegrityService.writeSignature(usersDb);
                if (json) {
                    System.out.println("{\"message\":\"Users DB initialized\",\"usersDb\":\"" + esc(usersDb.toString()) + "\"}");
                } else {
                    System.out.println("Users DB initialized at " + usersDb);
                }
                yield 0;
            }
            case "debug-security" -> {
                Path usersDb = Path.of(opts.getOrDefault("users-db", DEFAULT_USERS_DB_PATH.toString()));
                Path membersDb = Path.of(opts.getOrDefault("members-db", DEFAULT_CIRCLE_MEMBERS_DB_PATH.toString()));
                Path safeDb = Path.of(opts.getOrDefault("safe-db", DEFAULT_SAFE_DB_PATH.toString()));
                String output = debugSecurityReport(db, usersDb, membersDb, safeDb, json);
                System.out.println(output);
                yield 0;
            }
            case "create" -> {
                Incident incident = IncidentRepository.create(
                    db,
                    required(opts, "title"),
                    opts.getOrDefault("category", "auto"),
                    required(opts, "severity"),
                    required(opts, "location"),
                    required(opts, "details"),
                    parseBoolean(opts.getOrDefault("verified", "false"), "verified"),
                    opts.getOrDefault("source-type", "community"),
                    parseInt(opts.getOrDefault("corroboration-count", "1"), "corroboration-count"),
                    parseInt(opts.getOrDefault("expires-days", defaultExpiryDays(required(opts, "severity")) + ""), "expires-days"),
                    parseBoolean(opts.getOrDefault("ai-adjust", "false"), "ai-adjust")
                );
                if (json) {
                    System.out.println(incident.toJson());
                } else {
                    System.out.println(OutputFormatter.formatIncidentPretty(incident));
                }
                yield 0;
            }
            case "list" -> {
                IncidentRepository.ListOptions listOptions = new IncidentRepository.ListOptions();
                listOptions.keyword = opts.get("keyword");
                listOptions.category = opts.get("category");
                listOptions.severity = opts.get("severity");
                listOptions.status = opts.get("status");
                listOptions.location = opts.get("location");
                listOptions.verifiedOnly = parseBoolean(opts.getOrDefault("verified-only", "false"), "verified-only");
                listOptions.needsReviewOnly = parseBoolean(opts.getOrDefault("needs-review-only", "false"), "needs-review-only");
                listOptions.includeExpired = parseBoolean(opts.getOrDefault("include-expired", "false"), "include-expired");
                listOptions.minConfidence = opts.containsKey("min-confidence") ? parseDouble(opts.get("min-confidence"), "min-confidence") : null;

                List<Incident> incidents = IncidentRepository.list(db, listOptions);
                if (json) {
                    System.out.println(toJsonArray(incidents));
                } else {
                    System.out.println(OutputFormatter.formatIncidentListPretty(incidents));
                }
                yield 0;
            }
            case "update" -> {
                String verifiedRaw = opts.get("verified");
                Boolean verified = verifiedRaw == null ? null : parseBoolean(verifiedRaw, "verified");
                Integer corroborationCount = opts.containsKey("corroboration-count") ? parseInt(opts.get("corroboration-count"), "corroboration-count") : null;

                Incident updated = IncidentRepository.update(db, required(opts, "id"), opts.get("status"), verified, corroborationCount);
                if (json) {
                    System.out.println(updated.toJson());
                } else {
                    System.out.println(OutputFormatter.formatIncidentPretty(updated));
                }
                yield 0;
            }
            case "digest" -> {
                List<Incident> incidents = IncidentRepository.load(db);
                DigestService.DigestOptions digestOptions = new DigestService.DigestOptions();
                digestOptions.location = opts.get("location");
                digestOptions.category = opts.get("category");
                digestOptions.severity = opts.get("severity");
                digestOptions.period = opts.getOrDefault("period", "daily");
                if (!digestOptions.period.equals("daily") && !digestOptions.period.equals("weekly") && !digestOptions.period.equals("monthly")) {
                    throw new ValidationException("period must be one of daily, weekly, monthly");
                }
                digestOptions.includeUnverified = parseBoolean(opts.getOrDefault("include-unverified", "true"), "include-unverified");
                digestOptions.forceFallback = parseBoolean(opts.getOrDefault("force-fallback", "false"), "force-fallback");

                DigestService.DigestResult out = DigestService.digest(incidents, digestOptions);
                if (json) {
                    System.out.println("{\"mode\":\"" + esc(out.mode) + "\",\"text\":\"" + esc(out.text) + "\"}");
                } else {
                    System.out.println(OutputFormatter.formatDigestPretty(out));
                }
                yield 0;
            }
            case "signal-feed" -> {
                IncidentRepository.ListOptions listOptions = new IncidentRepository.ListOptions();
                listOptions.keyword = opts.get("keyword");
                listOptions.category = opts.get("category");
                listOptions.severity = opts.get("severity");
                listOptions.status = opts.get("status");
                listOptions.location = opts.get("location");
                listOptions.verifiedOnly = parseBoolean(opts.getOrDefault("verified-only", "false"), "verified-only");
                listOptions.needsReviewOnly = false;
                listOptions.includeExpired = false;
                listOptions.minConfidence = opts.containsKey("min-confidence") ? parseDouble(opts.get("min-confidence"), "min-confidence") : 0.60;
                boolean collapse = parseBoolean(opts.getOrDefault("collapse-clusters", "true"), "collapse-clusters");

                List<Incident> incidents = IncidentRepository.list(db, listOptions);
                if (collapse) {
                    incidents = IncidentRepository.collapseByCluster(incidents);
                }
                if (json) {
                    System.out.println(toJsonArray(incidents));
                } else {
                    System.out.println(OutputFormatter.formatIncidentListPretty(incidents));
                }
                yield 0;
            }
            case "clusters" -> {
                IncidentRepository.ListOptions listOptions = new IncidentRepository.ListOptions();
                listOptions.location = opts.get("location");
                listOptions.category = opts.get("category");
                listOptions.includeExpired = false;
                listOptions.minConfidence = opts.containsKey("min-confidence") ? parseDouble(opts.get("min-confidence"), "min-confidence") : null;
                List<Incident> incidents = IncidentRepository.list(db, listOptions);
                List<ReportInsightsService.ClusterSummary> clusters = ReportInsightsService.clusterSummaries(incidents);
                if (json) {
                    System.out.println(toJsonClusters(clusters));
                } else {
                    System.out.println(OutputFormatter.formatClustersPretty(clusters));
                }
                yield 0;
            }
            case "checklist" -> {
                Incident in = IncidentRepository.findById(db, required(opts, "id"));
                String scope = ReportInsightsService.classifyScope(in);
                List<String> steps = ReportInsightsService.checklist(in);
                if (json) {
                    System.out.println(toJsonChecklist(in, scope, steps));
                } else {
                    System.out.println(OutputFormatter.formatChecklistPretty(in, scope, steps));
                }
                yield 0;
            }
            case "prune-expired" -> {
                int removed = IncidentRepository.pruneExpired(db);
                if (json) {
                    System.out.println("{\"removed\":" + removed + "}");
                } else {
                    System.out.println("Pruned expired incidents: " + removed);
                }
                yield 0;
            }
            case "share-status" -> {
                Path safeDb = Path.of(opts.getOrDefault("safe-db", DEFAULT_SAFE_DB_PATH.toString()));
                Path membersDb = Path.of(opts.getOrDefault("members-db", DEFAULT_CIRCLE_MEMBERS_DB_PATH.toString()));
                SafeCircleService.StatusUpdate out = SafeCircleService.shareStatus(
                    safeDb,
                    membersDb,
                    required(opts, "circle"),
                    required(opts, "actor"),
                    required(opts, "sender"),
                    required(opts, "message"),
                    required(opts, "passphrase")
                );
                if (json) {
                    System.out.println(toJsonStatus(out));
                } else {
                    System.out.println("Safe-circle update stored for circle \"" + out.circle + "\" at " + out.createdAt);
                }
                yield 0;
            }
            case "view-status" -> {
                Path safeDb = Path.of(opts.getOrDefault("safe-db", DEFAULT_SAFE_DB_PATH.toString()));
                Path membersDb = Path.of(opts.getOrDefault("members-db", DEFAULT_CIRCLE_MEMBERS_DB_PATH.toString()));
                List<SafeCircleService.StatusUpdate> updates = SafeCircleService.viewStatus(
                    safeDb,
                    membersDb,
                    required(opts, "circle"),
                    required(opts, "actor"),
                    required(opts, "passphrase")
                );
                if (json) {
                    System.out.println(toJsonStatuses(updates));
                } else {
                    System.out.println(OutputFormatter.formatSafeStatusesPretty(updates));
                }
                yield 0;
            }
            case "create-circle" -> {
                Path membersDb = Path.of(opts.getOrDefault("members-db", DEFAULT_CIRCLE_MEMBERS_DB_PATH.toString()));
                SafeCircleService.createCircle(membersDb, required(opts, "circle"), required(opts, "owner"));
                if (json) {
                    System.out.println("{\"message\":\"circle created\",\"circle\":\"" + esc(required(opts, "circle")) + "\"}");
                } else {
                    System.out.println("Circle created: " + required(opts, "circle"));
                }
                yield 0;
            }
            case "add-circle-member" -> {
                Path membersDb = Path.of(opts.getOrDefault("members-db", DEFAULT_CIRCLE_MEMBERS_DB_PATH.toString()));
                SafeCircleService.addMember(
                    membersDb,
                    required(opts, "circle"),
                    required(opts, "actor"),
                    required(opts, "member")
                );
                if (json) {
                    System.out.println("{\"message\":\"member added\",\"circle\":\"" + esc(required(opts, "circle")) + "\",\"member\":\"" + esc(required(opts, "member")) + "\"}");
                } else {
                    System.out.println("Added member " + required(opts, "member") + " to circle " + required(opts, "circle"));
                }
                yield 0;
            }
            case "remove-circle-member" -> {
                Path membersDb = Path.of(opts.getOrDefault("members-db", DEFAULT_CIRCLE_MEMBERS_DB_PATH.toString()));
                SafeCircleService.removeMember(
                    membersDb,
                    required(opts, "circle"),
                    required(opts, "actor"),
                    required(opts, "member")
                );
                if (json) {
                    System.out.println("{\"message\":\"member removed\",\"circle\":\"" + esc(required(opts, "circle")) + "\",\"member\":\"" + esc(required(opts, "member")) + "\"}");
                } else {
                    System.out.println("Removed member " + required(opts, "member") + " from circle " + required(opts, "circle"));
                }
                yield 0;
            }
            case "set-circle-member-access" -> {
                Path membersDb = Path.of(opts.getOrDefault("members-db", DEFAULT_CIRCLE_MEMBERS_DB_PATH.toString()));
                boolean canManage = parseBoolean(required(opts, "can-manage"), "can-manage");
                SafeCircleService.setManageAccess(
                    membersDb,
                    required(opts, "circle"),
                    required(opts, "owner-actor"),
                    required(opts, "member"),
                    canManage
                );
                if (json) {
                    System.out.println("{\"message\":\"member access updated\",\"circle\":\"" + esc(required(opts, "circle")) + "\",\"member\":\"" + esc(required(opts, "member")) + "\",\"canManage\":" + canManage + "}");
                } else {
                    System.out.println("Updated member access for " + required(opts, "member") + " in circle " + required(opts, "circle") + " (canManage=" + canManage + ")");
                }
                yield 0;
            }
            case "list-circle-members" -> {
                Path membersDb = Path.of(opts.getOrDefault("members-db", DEFAULT_CIRCLE_MEMBERS_DB_PATH.toString()));
                List<SafeCircleService.MemberEntry> members = SafeCircleService.listMembers(
                    membersDb,
                    required(opts, "circle"),
                    required(opts, "actor")
                );
                if (json) {
                    System.out.println(toJsonMembers(members));
                } else {
                    if (members.isEmpty()) {
                        System.out.println("No active members.");
                    } else {
                        for (SafeCircleService.MemberEntry m : members) {
                            System.out.println(m.member + " (owner=" + m.isOwner + ", canManage=" + m.canManage + ", addedBy=" + m.addedBy + ", addedAt=" + m.addedAt + ")");
                        }
                    }
                }
                yield 0;
            }
            default -> {
                printHelp();
                yield 1;
            }
        };
    }

    private static int defaultExpiryDays(String severity) {
        return switch (severity) {
            case "high" -> 30;
            case "medium" -> 14;
            default -> 7;
        };
    }

    private static String required(Map<String, String> opts, String key) {
        String value = opts.get(key);
        if (value == null || value.isBlank()) {
            throw new ValidationException(key + " is required");
        }
        return value;
    }

    private static boolean parseBoolean(String raw, String name) {
        if (!"true".equals(raw) && !"false".equals(raw)) {
            throw new ValidationException(name + " must be true or false");
        }
        return Boolean.parseBoolean(raw);
    }

    private static int parseInt(String raw, String name) {
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException ex) {
            throw new ValidationException(name + " must be an integer");
        }
    }

    private static double parseDouble(String raw, String name) {
        try {
            return Double.parseDouble(raw);
        } catch (NumberFormatException ex) {
            throw new ValidationException(name + " must be a decimal number");
        }
    }

    private static Map<String, String> parseOptions(String[] args) {
        Map<String, String> map = new HashMap<>();
        for (int i = 1; i < args.length; i++) {
            String token = args[i];
            if (!token.startsWith("--")) {
                continue;
            }
            String key = token.substring(2);
            String value = "true";
            if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                value = args[i + 1];
                i++;
            }
            map.put(key, value);
        }
        return map;
    }

    private static String toJsonArray(List<Incident> incidents) {
        return "[" + incidents.stream().map(Incident::toJson).collect(Collectors.joining(",")) + "]";
    }

    private static String esc(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

    private static String toJsonClusters(List<ReportInsightsService.ClusterSummary> clusters) {
        return "[" + clusters.stream().map(c ->
            "{"
                + "\"clusterId\":\"" + esc(c.clusterId) + "\","
                + "\"count\":" + c.count + ","
                + "\"category\":\"" + esc(c.category) + "\","
                + "\"location\":\"" + esc(c.location) + "\","
                + "\"avgConfidence\":" + String.format(java.util.Locale.US, "%.4f", c.avgConfidence) + ","
                + "\"verifiedCount\":" + c.verifiedCount + ","
                + "\"scope\":\"" + esc(c.scope) + "\","
                + "\"sampleTitle\":\"" + esc(c.sampleTitle) + "\""
            + "}"
        ).collect(Collectors.joining(",")) + "]";
    }

    private static String toJsonChecklist(Incident incident, String scope, List<String> steps) {
        String stepsJson = "[" + steps.stream().map(s -> "\"" + esc(s) + "\"").collect(Collectors.joining(",")) + "]";
        return "{"
            + "\"incidentId\":\"" + esc(incident.id) + "\","
            + "\"title\":\"" + esc(incident.title) + "\","
            + "\"scope\":\"" + esc(scope) + "\","
            + "\"steps\":" + stepsJson
            + "}";
    }

    private static String toJsonStatus(SafeCircleService.StatusUpdate out) {
        return "{"
            + "\"circle\":\"" + esc(out.circle) + "\","
            + "\"sender\":\"" + esc(out.sender) + "\","
            + "\"createdAt\":\"" + esc(out.createdAt) + "\","
            + "\"message\":\"" + esc(out.message) + "\""
            + "}";
    }

    private static String toJsonStatuses(List<SafeCircleService.StatusUpdate> updates) {
        return "[" + updates.stream().map(CommunityGuardianApp::toJsonStatus).collect(Collectors.joining(",")) + "]";
    }

    private static String toJsonMembers(List<SafeCircleService.MemberEntry> members) {
        return "[" + members.stream().map(m ->
            "{"
                + "\"circle\":\"" + esc(m.circle) + "\","
                + "\"member\":\"" + esc(m.member) + "\","
                + "\"addedAt\":\"" + esc(m.addedAt) + "\","
                + "\"addedBy\":\"" + esc(m.addedBy) + "\","
                + "\"status\":\"" + esc(m.status) + "\","
                + "\"canManage\":" + m.canManage + ","
                + "\"isOwner\":" + m.isOwner
            + "}"
        ).collect(Collectors.joining(",")) + "]";
    }

    private static String debugSecurityReport(Path incidentsDb, Path usersDb, Path membersDb, Path safeDb, boolean json) throws IOException {
        boolean usersKeyStrong;
        boolean incidentKeyStrong;
        boolean integrityKeyStrong;
        String usersKeyVersion = "";
        String incidentKeyVersion = "";
        String integrityKeyVersion = "";
        try {
            KeyService.KeyRef usersRef = KeyService.activeUsersKey();
            usersKeyStrong = usersRef.key.length() >= 12;
            usersKeyVersion = usersRef.version;
        } catch (Exception ex) {
            usersKeyStrong = false;
        }
        try {
            KeyService.KeyRef incidentsRef = KeyService.activeIncidentKey();
            incidentKeyStrong = incidentsRef.key.length() >= 12;
            incidentKeyVersion = incidentsRef.version;
        } catch (Exception ex) {
            incidentKeyStrong = false;
        }
        try {
            KeyService.KeyRef integrityRef = KeyService.activeIntegrityKey();
            integrityKeyStrong = integrityRef.key.length() >= 12;
            integrityKeyVersion = integrityRef.version;
        } catch (Exception ex) {
            integrityKeyStrong = false;
        }

        boolean usersDbExists = Files.exists(usersDb);
        boolean usersDbEncrypted = false;
        boolean usersSigExists = Files.exists(Path.of(usersDb.toString() + ".sig"));
        if (usersDbExists) {
            String usersRaw = Files.readString(usersDb, StandardCharsets.UTF_8);
            usersDbEncrypted = usersRaw.startsWith("ENCv1:") || usersRaw.startsWith("ENCv2:");
        }

        boolean incidentsDbExists = Files.exists(incidentsDb);
        boolean incidentsSigExists = Files.exists(Path.of(incidentsDb.toString() + ".sig"));
        int encryptedLocationRows = 0;
        int totalIncidentRows = 0;
        if (incidentsDbExists) {
            List<Incident> incidents = IncidentRepository.load(incidentsDb);
            totalIncidentRows = incidents.size();

            List<String> lines = Files.readAllLines(incidentsDb, StandardCharsets.UTF_8);
            for (int i = 1; i < lines.size(); i++) {
                String line = lines.get(i).trim();
                if (line.isEmpty()) {
                    continue;
                }
                if (line.contains("ENCLOCv1:")) {
                    encryptedLocationRows++;
                }
            }
        }

        boolean membersDbExists = Files.exists(membersDb);
        boolean membersSigExists = Files.exists(Path.of(membersDb.toString() + ".sig"));
        boolean safeDbExists = Files.exists(safeDb);
        boolean safeSigExists = Files.exists(Path.of(safeDb.toString() + ".sig"));

        if (json) {
            return "{"
                + "\"usersKeyStrong\":" + usersKeyStrong + ","
                + "\"usersKeyVersion\":\"" + esc(usersKeyVersion) + "\","
                + "\"incidentKeyStrong\":" + incidentKeyStrong + ","
                + "\"incidentKeyVersion\":\"" + esc(incidentKeyVersion) + "\","
                + "\"integrityKeyStrong\":" + integrityKeyStrong + ","
                + "\"integrityKeyVersion\":\"" + esc(integrityKeyVersion) + "\","
                + "\"usersDbExists\":" + usersDbExists + ","
                + "\"usersDbEncrypted\":" + usersDbEncrypted + ","
                + "\"usersSigExists\":" + usersSigExists + ","
                + "\"incidentsDbExists\":" + incidentsDbExists + ","
                + "\"incidentsSigExists\":" + incidentsSigExists + ","
                + "\"incidentRows\":" + totalIncidentRows + ","
                + "\"encryptedLocationRows\":" + encryptedLocationRows + ","
                + "\"membersDbExists\":" + membersDbExists + ","
                + "\"membersSigExists\":" + membersSigExists + ","
                + "\"safeDbExists\":" + safeDbExists + ","
                + "\"safeSigExists\":" + safeSigExists
                + "}";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Security Debug").append("\n");
        sb.append("  USERS_DB_KEY strong (>=12): ").append(usersKeyStrong).append("\n");
        sb.append("  USERS_DB active key version: ").append(usersKeyVersion).append("\n");
        sb.append("  INCIDENT_DATA_KEY strong (>=12): ").append(incidentKeyStrong).append("\n");
        sb.append("  INCIDENT_DATA active key version: ").append(incidentKeyVersion).append("\n");
        sb.append("  DATA_INTEGRITY_KEY strong (>=12): ").append(integrityKeyStrong).append("\n");
        sb.append("  DATA_INTEGRITY active key version: ").append(integrityKeyVersion).append("\n");
        sb.append("  users.csv exists: ").append(usersDbExists).append("\n");
        sb.append("  users.csv encrypted envelope (ENCv1): ").append(usersDbEncrypted).append("\n");
        sb.append("  users.csv signature exists: ").append(usersSigExists).append("\n");
        sb.append("  incidents DB exists: ").append(incidentsDbExists).append("\n");
        sb.append("  incidents DB signature exists: ").append(incidentsSigExists).append("\n");
        sb.append("  incidents total rows: ").append(totalIncidentRows).append("\n");
        sb.append("  incidents encrypted location rows (ENCLOCv1): ").append(encryptedLocationRows).append("\n");
        sb.append("  circle_members DB exists: ").append(membersDbExists).append("\n");
        sb.append("  circle_members DB signature exists: ").append(membersSigExists).append("\n");
        sb.append("  safe_circle_updates DB exists: ").append(safeDbExists).append("\n");
        sb.append("  safe_circle_updates DB signature exists: ").append(safeSigExists);
        return sb.toString();
    }

    private static void printHelp() {
        System.out.println("Community Guardian CLI");
        System.out.println("Commands:");
        System.out.println("  start [--db data/incidents_db.csv] [--users-db data/users.csv] [--safe-db data/safe_circle_updates.csv] [--members-db data/circle_members.csv]");
        System.out.println("  init-users [--users-db data/users.csv] [--format pretty|json]");
        System.out.println("  debug-security [--db data/incidents_db.csv] [--users-db data/users.csv] [--safe-db data/safe_circle_updates.csv] [--members-db data/circle_members.csv] [--format pretty|json]");
        System.out.println("  create-account --username NAME --role user|reviewer --password SECRET --location CITY [--users-db data/users.csv] [--format pretty|json]");
        System.out.println("  init-db [--db data/incidents_db.csv] [--format pretty|json]");
        System.out.println("  create --title ... [--category physical|digital|auto] --severity low|medium|high --location ... --details ... [--verified true|false] [--source-type community|official|news|sensor|unknown] [--corroboration-count N (claimed, system validates)] [--expires-days N] [--ai-adjust true|false]");
        System.out.println("  list [--keyword q] [--location city] [--category physical|digital] [--severity low|medium|high] [--status open|monitoring|resolved] [--verified-only true|false] [--needs-review-only true|false] [--min-confidence 0.0-1.0] [--include-expired true|false] [--format pretty|json]");
        System.out.println("  update --id INCIDENT_ID [--status open|monitoring|resolved] [--verified true|false] [--corroboration-count N (claimed, ignored for scoring)]");
        System.out.println("  digest [--location city] [--period daily|weekly|monthly] [--category physical|digital] [--severity low|medium|high] [--include-unverified true|false] [--force-fallback true|false] [--format pretty|json]");
        System.out.println("  signal-feed [--location city] [--category physical|digital] [--severity low|medium|high] [--min-confidence 0.0-1.0] [--verified-only true|false] [--collapse-clusters true|false] [--format pretty|json]");
        System.out.println("  clusters [--location city] [--category physical|digital] [--min-confidence 0.0-1.0] [--format pretty|json]");
        System.out.println("  checklist --id INCIDENT_ID [--format pretty|json]");
        System.out.println("  prune-expired [--db data/incidents_db.csv] [--format pretty|json]");
        System.out.println("  create-circle --circle NAME --owner USER [--members-db data/circle_members.csv] [--format pretty|json]");
        System.out.println("  add-circle-member --circle NAME --actor USER --member USER [--members-db data/circle_members.csv] [--format pretty|json]");
        System.out.println("  remove-circle-member --circle NAME --actor USER --member USER [--members-db data/circle_members.csv] [--format pretty|json]");
        System.out.println("  set-circle-member-access --circle NAME --owner-actor USER --member USER --can-manage true|false [--members-db data/circle_members.csv] [--format pretty|json]");
        System.out.println("  list-circle-members --circle NAME --actor USER [--members-db data/circle_members.csv] [--format pretty|json]");
        System.out.println("  share-status --circle NAME --actor USER --sender USER --message TEXT --passphrase SECRET [--safe-db data/safe_circle_updates.csv] [--members-db data/circle_members.csv] [--format pretty|json]");
        System.out.println("  view-status --circle NAME --actor USER --passphrase SECRET [--safe-db data/safe_circle_updates.csv] [--members-db data/circle_members.csv] [--format pretty|json]");
    }
}
