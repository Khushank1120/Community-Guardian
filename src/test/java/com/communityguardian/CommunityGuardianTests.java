package com.communityguardian;

import com.communityguardian.exception.ValidationException;
import com.communityguardian.model.Incident;
import com.communityguardian.repository.IncidentRepository;
import com.communityguardian.service.DigestService;
import com.communityguardian.service.SafeCircleService;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class CommunityGuardianTests {
    public static void main(String[] args) throws Exception {
        initSecurityTestConfig();
        ConfidenceServiceTests.runAll();
        DigestServiceTests.runAll();
        IncidentRepositoryTests.runAll();
        ReportInsightsServiceTests.runAll();
        SafeCircleServiceTests.runAll();
        OutputFormatterTests.runAll();
        AuthServiceTests.runAll();
        CategorizationServiceTests.runAll();

        testHappyPathCreateFilterAndDigestFallback();
        testEdgeCaseInvalidDetailsRejected();
        testLowConfidenceGoesToNeedsReview();
        testExpiredIncidentsExcludedByDefault();
        testUpdateRecomputesConfidenceAndClearsReviewWhenVerified();
        testClusterCollapseReducesDuplicateNoise();
        testSafeCircleEncryptionRoundTrip();
        System.out.println("All tests passed (service + integration).");
    }

    private static void initSecurityTestConfig() {
        System.setProperty("users.db.key", "UsersTestKey@123456");
        System.setProperty("incident.data.key", "IncidentTestKey@123456");
        System.setProperty("data.integrity.key", "IntegrityTestKey@123456");
        System.setProperty("audit.log.path", "/tmp/community-guardian-audit.log");
        System.setProperty("auth.max.failed", "5");
        System.setProperty("auth.lockout.minutes", "15");
    }

    static void testHappyPathCreateFilterAndDigestFallback() throws IOException {
        Path tmp = Files.createTempFile("guardian", ".csv");
        try {
            IncidentRepository.initDb(Path.of("data", "sample_incidents.csv"), tmp);

            Incident created = IncidentRepository.create(
                tmp,
                "Community wifi router exposed",
                "digital",
                "high",
                "Brooklyn",
                "Default admin password was observed on multiple home routers.",
                true,
                "official",
                2,
                14,
                false
            );
            assertTrue(created.category.equals("digital"), "created category should be digital");
            assertTrue(created.confidenceScore >= 0.7, "created confidence should be high");

            IncidentRepository.ListOptions opts = new IncidentRepository.ListOptions();
            opts.keyword = "router";
            opts.category = "digital";
            opts.severity = "high";
            opts.minConfidence = 0.7;
            List<Incident> filtered = IncidentRepository.list(tmp, opts);
            assertTrue(filtered.size() == 1, "filtered list should have one incident");
            assertTrue(filtered.get(0).title.equals("Community wifi router exposed"), "filtered title mismatch");

            List<Incident> loaded = IncidentRepository.load(tmp);
            DigestService.DigestOptions digestOptions = new DigestService.DigestOptions();
            digestOptions.location = "Brooklyn";
            digestOptions.period = "monthly";
            digestOptions.forceFallback = true;
            DigestService.DigestResult digest = DigestService.digest(loaded, digestOptions);
            assertTrue(digest.mode.equals("fallback"), "digest mode should be fallback");
            assertTrue(digest.text.contains("Next steps"), "digest should include next steps");
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    static void testEdgeCaseInvalidDetailsRejected() throws IOException {
        Path tmp = Files.createTempFile("guardian", ".csv");
        try {
            String seed = Files.readString(Path.of("data", "sample_incidents.csv"), StandardCharsets.UTF_8);
            Files.writeString(tmp, seed, StandardCharsets.UTF_8);

            boolean thrown = false;
            try {
                IncidentRepository.create(tmp, "Bad payload", "digital", "medium", "Queens", "Too short", false, "community", 1, 7, false);
            } catch (ValidationException ex) {
                thrown = true;
            }
            assertTrue(thrown, "expected validation error for short details");
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    static void testLowConfidenceGoesToNeedsReview() throws IOException {
        Path tmp = Files.createTempFile("guardian", ".csv");
        try {
            IncidentRepository.initDb(Path.of("data", "sample_incidents.csv"), tmp);

            Incident created = IncidentRepository.create(
                tmp,
                "Anonymous post about fake tax refund portal",
                "digital",
                "high",
                "Queens",
                "Single unverified post claims a portal steals credentials.",
                false,
                "unknown",
                0,
                7,
                false
            );

            assertTrue(created.confidenceScore < 0.60, "expected low confidence score");
            assertTrue(created.needsReview, "low-confidence unverified incident should need review");

            IncidentRepository.ListOptions opts = new IncidentRepository.ListOptions();
            opts.needsReviewOnly = true;
            List<Incident> reviewQueue = IncidentRepository.list(tmp, opts);
            assertTrue(reviewQueue.stream().anyMatch(i -> i.id.equals(created.id)), "incident should appear in review queue");
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    static void testExpiredIncidentsExcludedByDefault() throws IOException {
        Path tmp = Files.createTempFile("guardian", ".csv");
        try {
            IncidentRepository.initDb(Path.of("data", "sample_incidents.csv"), tmp);
            List<Incident> all = IncidentRepository.load(tmp);
            Incident first = all.get(0);
            first.expiresAt = "2020-01-01T00:00:00Z";
            IncidentRepository.save(tmp, all);

            IncidentRepository.ListOptions hiddenExpired = new IncidentRepository.ListOptions();
            hiddenExpired.includeExpired = false;
            List<Incident> withoutExpired = IncidentRepository.list(tmp, hiddenExpired);
            assertTrue(withoutExpired.stream().noneMatch(i -> i.id.equals(first.id)), "expired incident should be hidden");

            IncidentRepository.ListOptions includeExpired = new IncidentRepository.ListOptions();
            includeExpired.includeExpired = true;
            List<Incident> withExpired = IncidentRepository.list(tmp, includeExpired);
            assertTrue(withExpired.stream().anyMatch(i -> i.id.equals(first.id)), "expired incident should be visible when requested");
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    static void testUpdateRecomputesConfidenceAndClearsReviewWhenVerified() throws IOException {
        Path tmp = Files.createTempFile("guardian", ".csv");
        try {
            IncidentRepository.initDb(Path.of("data", "sample_incidents.csv"), tmp);
            Incident low = IncidentRepository.create(
                tmp,
                "Unverified local outage rumor",
                "physical",
                "medium",
                "Queens",
                "Initial report from one unverified account without corroboration.",
                false,
                "unknown",
                0,
                7,
                false
            );
            assertTrue(low.needsReview, "new incident should start in review");

            Incident updated = IncidentRepository.update(tmp, low.id, "monitoring", true, 3);
            assertTrue(!updated.needsReview, "verified incident should leave review queue");
            assertTrue(updated.confidenceScore > low.confidenceScore, "confidence should increase after verification");
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    static void testClusterCollapseReducesDuplicateNoise() throws IOException {
        Path tmp = Files.createTempFile("guardian", ".csv");
        try {
            IncidentRepository.initDb(Path.of("data", "sample_incidents.csv"), tmp);
            IncidentRepository.create(
                tmp,
                "Suspicious QR phishing flyers",
                "digital",
                "medium",
                "Brooklyn",
                "Residents reported QR stickers linking to credential-harvest pages near transit stops.",
                false,
                "community",
                2,
                7,
                false
            );
            IncidentRepository.create(
                tmp,
                "Suspicious QR phishing flyers at bus stop",
                "digital",
                "medium",
                "Brooklyn",
                "More residents reported the same QR phishing stickers around the same routes.",
                false,
                "community",
                2,
                7,
                false
            );

            IncidentRepository.ListOptions opts = new IncidentRepository.ListOptions();
            opts.location = "Brooklyn";
            opts.minConfidence = 0.50;
            List<Incident> all = IncidentRepository.list(tmp, opts);
            List<Incident> collapsed = IncidentRepository.collapseByCluster(all);
            assertTrue(collapsed.size() < all.size(), "collapsed feed should be smaller than full feed");
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    static void testSafeCircleEncryptionRoundTrip() throws IOException {
        Path safeDb = Files.createTempFile("safe-circle", ".csv");
        Path membersDb = Files.createTempFile("safe-members", ".csv");
        try {
            SafeCircleService.createCircle(membersDb, "family-guardians", "khushank");
            SafeCircleService.shareStatus(
                safeDb,
                membersDb,
                "family-guardians",
                "khushank",
                "khushank",
                "I reached home safely and enabled router MFA.",
                "strongpass123"
            );

            List<SafeCircleService.StatusUpdate> updates = SafeCircleService.viewStatus(safeDb, membersDb, "family-guardians", "khushank", "strongpass123");
            assertTrue(updates.size() == 1, "should decrypt one status update");
            assertTrue(updates.get(0).message.contains("reached home safely"), "decrypted message content mismatch");

            boolean threw = false;
            try {
                SafeCircleService.viewStatus(safeDb, membersDb, "family-guardians", "khushank", "wrong-passphrase");
            } catch (ValidationException ex) {
                threw = true;
            }
            assertTrue(threw, "wrong passphrase should fail decryption");
        } finally {
            Files.deleteIfExists(safeDb);
            Files.deleteIfExists(membersDb);
        }
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
