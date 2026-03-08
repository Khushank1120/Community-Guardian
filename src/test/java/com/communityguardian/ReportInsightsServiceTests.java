package com.communityguardian;

import com.communityguardian.model.Incident;
import com.communityguardian.service.ReportInsightsService;

import java.util.List;

public class ReportInsightsServiceTests {
    public static void runAll() {
        testScopeClassification();
        testChecklistGeneration();
        testClusterSummaryGrouping();
    }

    static void testScopeClassification() {
        Incident in = new Incident();
        in.sourceType = "official";
        in.corroborationCount = 2;
        in.confidenceScore = 0.9;

        String scope = ReportInsightsService.classifyScope(in);
        TestAssertions.assertEquals("widespread", scope, "scope should be widespread");
    }

    static void testChecklistGeneration() {
        Incident in = new Incident();
        in.category = "digital";
        in.title = "Phishing attempt";
        in.details = "Credential harvesting link reported";

        List<String> steps = ReportInsightsService.checklist(in);
        TestAssertions.assertTrue(steps.size() == 3, "checklist should have 3 steps");
        TestAssertions.assertTrue(steps.get(0).toLowerCase().contains("verify") || steps.get(0).toLowerCase().contains("click"), "first step should be relevant");
    }

    static void testClusterSummaryGrouping() {
        Incident a = new Incident();
        a.clusterId = "digital|brooklyn|qr-phishing";
        a.category = "digital";
        a.location = "Brooklyn";
        a.confidenceScore = 0.7;
        a.verified = true;
        a.title = "QR phishing";
        a.sourceType = "community";
        a.corroborationCount = 2;

        Incident b = new Incident();
        b.clusterId = "digital|brooklyn|qr-phishing";
        b.category = "digital";
        b.location = "Brooklyn";
        b.confidenceScore = 0.6;
        b.verified = false;
        b.title = "QR phishing duplicate";
        b.sourceType = "community";
        b.corroborationCount = 2;

        List<ReportInsightsService.ClusterSummary> clusters = ReportInsightsService.clusterSummaries(List.of(a, b));
        TestAssertions.assertTrue(clusters.size() == 1, "expected one grouped cluster");
        TestAssertions.assertTrue(clusters.get(0).count == 2, "cluster count should be 2");
    }
}
