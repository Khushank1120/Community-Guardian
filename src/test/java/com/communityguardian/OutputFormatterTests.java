package com.communityguardian;

import com.communityguardian.cli.OutputFormatter;
import com.communityguardian.model.Incident;
import com.communityguardian.service.DigestService;

import java.util.List;

public class OutputFormatterTests {
    public static void runAll() {
        testIncidentListPretty();
        testDigestPretty();
    }

    static void testIncidentListPretty() {
        Incident in = new Incident();
        in.id = "id-1";
        in.category = "digital";
        in.location = "Brooklyn";
        in.severity = "medium";
        in.status = "open";
        in.needsReview = true;
        in.verified = false;
        in.confidenceScore = 0.58;
        in.title = "Phishing attempt";
        in.clusterId = "digital|brooklyn|phishing";

        String table = OutputFormatter.formatIncidentListPretty(List.of(in));
        TestAssertions.assertTrue(table.contains("Total incidents: 1"), "table should include total count");
    }

    static void testDigestPretty() {
        DigestService.DigestResult result = new DigestService.DigestResult("fallback", "Line1\nLine2");
        String pretty = OutputFormatter.formatDigestPretty(result);
        TestAssertions.assertTrue(pretty.contains("Mode : fallback"), "pretty digest should include mode");
    }
}
