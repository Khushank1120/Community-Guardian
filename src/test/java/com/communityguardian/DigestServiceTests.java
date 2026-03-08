package com.communityguardian;

import com.communityguardian.model.Incident;
import com.communityguardian.service.DigestService;

import java.util.List;

public class DigestServiceTests {
    public static void runAll() {
        testFallbackDigestWithFilters();
        testNoneWhenNoMatches();
    }

    static void testFallbackDigestWithFilters() {
        Incident in = new Incident();
        in.id = "1";
        in.title = "Phishing campaign";
        in.category = "digital";
        in.severity = "high";
        in.location = "Brooklyn";
        in.details = "Credential theft attempt";
        in.verified = false;
        in.status = "open";
        in.sourceType = "community";
        in.corroborationCount = 1;
        in.confidenceScore = 0.58;
        in.needsReview = true;
        in.reportedAt = java.time.Instant.now().toString();
        in.expiresAt = "";
        in.clusterId = "digital|brooklyn|phishing-campaign";

        DigestService.DigestOptions options = new DigestService.DigestOptions();
        options.location = "Brooklyn";
        options.period = "daily";
        options.forceFallback = true;

        DigestService.DigestResult result = DigestService.digest(List.of(in), options);
        TestAssertions.assertEquals("fallback", result.mode, "digest mode should be fallback");
        TestAssertions.assertTrue(result.text.contains("Next steps"), "fallback digest should include next steps");
    }

    static void testNoneWhenNoMatches() {
        Incident in = new Incident();
        in.location = "Queens";
        in.reportedAt = java.time.Instant.now().toString();
        in.expiresAt = "";

        DigestService.DigestOptions options = new DigestService.DigestOptions();
        options.location = "Brooklyn";
        options.forceFallback = true;

        DigestService.DigestResult result = DigestService.digest(List.of(in), options);
        TestAssertions.assertEquals("none", result.mode, "expected none mode for empty scope");
    }
}
