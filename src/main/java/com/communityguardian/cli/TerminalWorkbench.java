package com.communityguardian.cli;

import com.communityguardian.auth.AuthService;
import com.communityguardian.exception.ValidationException;
import com.communityguardian.model.Incident;
import com.communityguardian.repository.IncidentRepository;
import com.communityguardian.service.DigestService;
import com.communityguardian.service.ReportInsightsService;
import com.communityguardian.service.SafeCircleService;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.List;

public class TerminalWorkbench {
    public static void start(Path dbPath, Path usersDbPath, Path safeDbPath, Path membersDbPath) throws IOException {
        AuthService.ensureDefaultUsers(usersDbPath);

        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Community Guardian Terminal");
        System.out.println("Login with your account.");
        System.out.println("Default demo user: demo_user / UserDemo@1234");
        System.out.println("Default reviewer: demo_reviewer / ReviewDemo@1234");

        AuthService.Session session = login(reader, usersDbPath);
        System.out.println("\nWelcome, " + session.username + " (" + session.role + "), location=" + session.defaultLocation + "\n");

        if ("reviewer".equals(session.role)) {
            reviewerMenu(reader, dbPath, safeDbPath, membersDbPath, session.username, session.defaultLocation);
        } else {
            userMenu(reader, dbPath, safeDbPath, membersDbPath, session.username, session.defaultLocation);
        }
    }

    private static AuthService.Session login(BufferedReader reader, Path usersDbPath) throws IOException {
        while (true) {
            System.out.println();
            System.out.println("Authentication");
            System.out.println("1) Login");
            System.out.println("2) Sign up");
            System.out.println("0) Exit");
            String action = prompt(reader, "Choose option");

            if ("0".equals(action)) {
                throw new ValidationException("session ended by user");
            }

            if ("2".equals(action)) {
                signUpFlow(reader, usersDbPath);
                continue;
            }

            if (!"1".equals(action)) {
                System.out.println("Invalid option.");
                continue;
            }

            String username = prompt(reader, "Username");
            String password = prompt(reader, "Password");
            try {
                return AuthService.authenticate(usersDbPath, username, password);
            } catch (ValidationException ex) {
                System.out.println("Login failed: " + ex.getMessage());
            }
        }
    }

    private static void signUpFlow(BufferedReader reader, Path usersDbPath) throws IOException {
        String username = prompt(reader, "New username");
        String role = prompt(reader, "Role (user|reviewer)");
        String password = prompt(reader, "Password (min 12, upper/lower/number/special)");
        String location = prompt(reader, "Default location (e.g., Brooklyn)");
        try {
            AuthService.createAccount(usersDbPath, username, role, password, location);
            System.out.println("Account created. You can now login.");
        } catch (ValidationException ex) {
            System.out.println("Signup failed: " + ex.getMessage());
        }
    }

    private static void userMenu(BufferedReader reader, Path dbPath, Path safeDbPath, Path membersDbPath, String currentUser, String defaultLocation) throws IOException {
        while (true) {
            System.out.println("User Menu");
            System.out.println("1) Create incident report");
            System.out.println("2) View signal feed");
            System.out.println("3) Generate digest");
            System.out.println("4) View checklist by incident ID");
            System.out.println("5) Circle settings");
            System.out.println("6) Share safe-circle status");
            System.out.println("7) View safe-circle updates");
            System.out.println("0) Logout");

            String choice = prompt(reader, "Choose option");
            try {
                switch (choice) {
                    case "1" -> createIncidentFlow(reader, dbPath);
                    case "2" -> viewSignalFeedFlow(reader, dbPath);
                    case "3" -> digestFlow(reader, dbPath, defaultLocation);
                    case "4" -> checklistFlow(reader, dbPath);
                    case "5" -> circleSettingsMenu(reader, safeDbPath, membersDbPath, currentUser);
                    case "6" -> shareStatusFlow(reader, safeDbPath, membersDbPath, currentUser);
                    case "7" -> viewStatusFlow(reader, safeDbPath, membersDbPath, currentUser);
                    case "0" -> {
                        System.out.println("Logged out.");
                        return;
                    }
                    default -> System.out.println("Invalid option.\n");
                }
            } catch (ValidationException ex) {
                System.out.println("Error: " + ex.getMessage() + "\n");
            }
        }
    }

    private static void reviewerMenu(BufferedReader reader, Path dbPath, Path safeDbPath, Path membersDbPath, String currentUser, String defaultLocation) throws IOException {
        while (true) {
            System.out.println("Reviewer Menu");
            System.out.println("1) View review queue");
            System.out.println("2) Verify/update incident");
            System.out.println("3) View clusters");
            System.out.println("4) Prune expired incidents");
            System.out.println("5) Generate digest");
            System.out.println("0) Logout");

            String choice = prompt(reader, "Choose option");
            try {
                switch (choice) {
                    case "1" -> reviewQueueFlow(dbPath);
                    case "2" -> updateIncidentFlow(reader, dbPath);
                    case "3" -> clustersFlow(reader, dbPath);
                    case "4" -> pruneExpiredFlow(dbPath);
                    case "5" -> digestFlow(reader, dbPath, defaultLocation);
                    case "0" -> {
                        System.out.println("Logged out.");
                        return;
                    }
                    default -> System.out.println("Invalid option.\n");
                }
            } catch (ValidationException ex) {
                System.out.println("Error: " + ex.getMessage() + "\n");
            }
        }
    }

    private static void circleSettingsMenu(BufferedReader reader, Path safeDbPath, Path membersDbPath, String currentUser) throws IOException {
        while (true) {
            System.out.println("Circle Settings");
            System.out.println("1) Create circle");
            System.out.println("2) Add circle member");
            System.out.println("3) Remove circle member");
            System.out.println("4) Grant/revoke member management access (owner only)");
            System.out.println("5) List circle members");
            System.out.println("0) Back");

            String choice = prompt(reader, "Choose option");
            try {
                switch (choice) {
                    case "1" -> createCircleFlow(reader, membersDbPath, currentUser);
                    case "2" -> addCircleMemberFlow(reader, membersDbPath, currentUser);
                    case "3" -> removeCircleMemberFlow(reader, membersDbPath, currentUser);
                    case "4" -> setMemberAccessFlow(reader, membersDbPath, currentUser);
                    case "5" -> listCircleMembersFlow(reader, membersDbPath, currentUser);
                    case "0" -> {
                        System.out.println();
                        return;
                    }
                    default -> System.out.println("Invalid option.\n");
                }
            } catch (ValidationException ex) {
                System.out.println("Error: " + ex.getMessage() + "\n");
            }
        }
    }

    private static void createIncidentFlow(BufferedReader reader, Path dbPath) throws IOException {
        String title = prompt(reader, "Title");
        String category = prompt(reader, "Category (physical|digital|auto, blank=auto)");
        if (category.isBlank()) {
            category = "auto";
        }
        String severity = prompt(reader, "Severity (low|medium|high)");
        String location = prompt(reader, "Location");
        String details = prompt(reader, "Details");
        String sourceType = prompt(reader, "Source type (community|official|news|sensor|unknown)");
        int corroboration = parseInt(prompt(reader, "Claimed corroboration count"), "corroboration count");
        boolean verified = parseBoolean(prompt(reader, "Verified (true|false)"), "verified");
        boolean aiAdjust = parseBoolean(prompt(reader, "Use AI confidence adjust (true|false)"), "ai adjust");

        int expiryDays = switch (severity) {
            case "high" -> 30;
            case "medium" -> 14;
            default -> 7;
        };

        Incident created = IncidentRepository.create(
            dbPath,
            title,
            category,
            severity,
            location,
            details,
            verified,
            sourceType,
            corroboration,
            expiryDays,
            aiAdjust
        );

        System.out.println(OutputFormatter.formatIncidentPretty(created));
        System.out.println();
    }

    private static void viewSignalFeedFlow(BufferedReader reader, Path dbPath) throws IOException {
        String location = prompt(reader, "Location filter (blank for all)");
        String minRaw = prompt(reader, "Minimum confidence (blank for 0.60)");
        double min = minRaw.isBlank() ? 0.60 : Double.parseDouble(minRaw);

        IncidentRepository.ListOptions options = new IncidentRepository.ListOptions();
        options.location = location.isBlank() ? null : location;
        options.minConfidence = min;
        options.includeExpired = false;

        List<Incident> incidents = IncidentRepository.list(dbPath, options);
        incidents = IncidentRepository.collapseByCluster(incidents);
        System.out.println(OutputFormatter.formatIncidentListPretty(incidents));
        System.out.println();
    }

    private static void reviewQueueFlow(Path dbPath) throws IOException {
        IncidentRepository.ListOptions options = new IncidentRepository.ListOptions();
        options.needsReviewOnly = true;
        options.includeExpired = false;
        List<Incident> queue = IncidentRepository.list(dbPath, options);
        System.out.println(OutputFormatter.formatIncidentListPretty(queue));
        System.out.println();
    }

    private static void updateIncidentFlow(BufferedReader reader, Path dbPath) throws IOException {
        String id = prompt(reader, "Incident ID");
        String status = prompt(reader, "Status (open|monitoring|resolved)");
        boolean verified = parseBoolean(prompt(reader, "Verified (true|false)"), "verified");
        int corroboration = parseInt(prompt(reader, "Claimed corroboration count"), "corroboration count");

        Incident updated = IncidentRepository.update(dbPath, id, status, verified, corroboration);
        System.out.println(OutputFormatter.formatIncidentPretty(updated));
        System.out.println();
    }

    private static void clustersFlow(BufferedReader reader, Path dbPath) throws IOException {
        String location = prompt(reader, "Location filter (blank for all)");
        IncidentRepository.ListOptions options = new IncidentRepository.ListOptions();
        options.location = location.isBlank() ? null : location;
        options.includeExpired = false;
        List<Incident> incidents = IncidentRepository.list(dbPath, options);
        System.out.println(OutputFormatter.formatClustersPretty(ReportInsightsService.clusterSummaries(incidents)));
        System.out.println();
    }

    private static void checklistFlow(BufferedReader reader, Path dbPath) throws IOException {
        String id = prompt(reader, "Incident ID");
        Incident in = IncidentRepository.findById(dbPath, id);
        String scope = ReportInsightsService.classifyScope(in);
        List<String> steps = ReportInsightsService.checklist(in);
        System.out.println(OutputFormatter.formatChecklistPretty(in, scope, steps));
        System.out.println();
    }

    private static void digestFlow(BufferedReader reader, Path dbPath, String defaultLocation) throws IOException {
        String location = prompt(reader, "Location filter (blank=profile location, ALL=all locations)");
        String period = prompt(reader, "Period (daily|weekly|monthly)");
        if (!period.equals("daily") && !period.equals("weekly") && !period.equals("monthly")) {
            throw new ValidationException("period must be daily, weekly, or monthly");
        }

        DigestService.DigestOptions options = new DigestService.DigestOptions();
        if (location.isBlank()) {
            options.location = defaultLocation;
        } else if ("ALL".equalsIgnoreCase(location)) {
            options.location = null;
        } else {
            options.location = location;
        }
        options.period = period;
        options.includeUnverified = true;
        options.forceFallback = false;

        DigestService.DigestResult result = DigestService.digest(IncidentRepository.load(dbPath), options);
        System.out.println(OutputFormatter.formatDigestPretty(result));
        System.out.println();
    }

    private static void pruneExpiredFlow(Path dbPath) throws IOException {
        int removed = IncidentRepository.pruneExpired(dbPath);
        System.out.println("Pruned expired incidents: " + removed + "\n");
    }

    private static void createCircleFlow(BufferedReader reader, Path membersDbPath, String currentUser) throws IOException {
        String circle = prompt(reader, "Circle name");
        SafeCircleService.createCircle(membersDbPath, circle, currentUser);
        System.out.println("Circle created with owner: " + currentUser + "\n");
    }

    private static void addCircleMemberFlow(BufferedReader reader, Path membersDbPath, String currentUser) throws IOException {
        String circle = prompt(reader, "Circle name");
        String member = prompt(reader, "Member username to add");
        SafeCircleService.addMember(membersDbPath, circle, currentUser, member);
        System.out.println("Added " + member + " to circle " + circle + "\n");
    }

    private static void removeCircleMemberFlow(BufferedReader reader, Path membersDbPath, String currentUser) throws IOException {
        String circle = prompt(reader, "Circle name");
        String member = prompt(reader, "Member username to remove");
        SafeCircleService.removeMember(membersDbPath, circle, currentUser, member);
        System.out.println("Removed " + member + " from circle " + circle + "\n");
    }

    private static void setMemberAccessFlow(BufferedReader reader, Path membersDbPath, String currentUser) throws IOException {
        String circle = prompt(reader, "Circle name");
        String member = prompt(reader, "Member username");
        boolean canManage = parseBoolean(prompt(reader, "Can manage members (true|false)"), "can manage");
        SafeCircleService.setManageAccess(membersDbPath, circle, currentUser, member, canManage);
        System.out.println("Updated member access for " + member + " in circle " + circle + " (canManage=" + canManage + ")\n");
    }

    private static void listCircleMembersFlow(BufferedReader reader, Path membersDbPath, String currentUser) throws IOException {
        String circle = prompt(reader, "Circle name");
        List<SafeCircleService.MemberEntry> members = SafeCircleService.listMembers(membersDbPath, circle, currentUser);
        if (members.isEmpty()) {
            System.out.println("No active members.\n");
            return;
        }
        for (SafeCircleService.MemberEntry m : members) {
            System.out.println(m.member + " (addedBy=" + m.addedBy + ", addedAt=" + m.addedAt + ")");
        }
        System.out.println();
    }

    private static void shareStatusFlow(BufferedReader reader, Path safeDbPath, Path membersDbPath, String currentUser) throws IOException {
        String circle = prompt(reader, "Circle name");
        String message = prompt(reader, "Status message");
        String passphrase = prompt(reader, "Circle passphrase");

        SafeCircleService.shareStatus(safeDbPath, membersDbPath, circle, currentUser, currentUser, message, passphrase);
        System.out.println("Safe-circle status shared.\n");
    }

    private static void viewStatusFlow(BufferedReader reader, Path safeDbPath, Path membersDbPath, String currentUser) throws IOException {
        String circle = prompt(reader, "Circle name");
        String passphrase = prompt(reader, "Circle passphrase");
        List<SafeCircleService.StatusUpdate> updates = SafeCircleService.viewStatus(safeDbPath, membersDbPath, circle, currentUser, passphrase);
        System.out.println(OutputFormatter.formatSafeStatusesPretty(updates));
        System.out.println();
    }

    private static String prompt(BufferedReader reader, String label) throws IOException {
        System.out.print(label + ": ");
        String value = reader.readLine();
        return value == null ? "" : value.trim();
    }

    private static int parseInt(String raw, String name) {
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException ex) {
            throw new ValidationException(name + " must be an integer");
        }
    }

    private static boolean parseBoolean(String raw, String name) {
        if (!raw.equals("true") && !raw.equals("false")) {
            throw new ValidationException(name + " must be true or false");
        }
        return Boolean.parseBoolean(raw);
    }
}
