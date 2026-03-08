package com.communityguardian;

import com.communityguardian.model.Incident;
import com.communityguardian.service.ConfidenceService;

public class ConfidenceServiceTests {
    public static void runAll() {
        testRuleScoreIncreasesWithTrustAndCorroboration();
        testReviewFlagForLowConfidenceUnverified();
    }

    static void testRuleScoreIncreasesWithTrustAndCorroboration() {
        Incident low = new Incident();
        low.sourceType = "unknown";
        low.corroborationCount = 0;
        low.verified = false;
        low.severity = "high";
        low.details = "short details but over ten";

        Incident high = new Incident();
        high.sourceType = "official";
        high.corroborationCount = 3;
        high.verified = true;
        high.severity = "medium";
        high.details = "This report has substantial detail and a clear timeline to increase signal quality in scoring.";

        double lowScore = ConfidenceService.computeRuleScore(low);
        double highScore = ConfidenceService.computeRuleScore(high);

        TestAssertions.assertTrue(highScore > lowScore, "trusted report should score higher");
    }

    static void testReviewFlagForLowConfidenceUnverified() {
        Incident in = new Incident();
        in.sourceType = "unknown";
        in.corroborationCount = 0;
        in.verified = false;
        in.severity = "high";
        in.details = "Unverified claim with limited information.";

        in.confidenceScore = ConfidenceService.computeRuleScore(in);
        boolean review = ConfidenceService.shouldFlagForReview(in);
        TestAssertions.assertTrue(review, "low confidence unverified should be flagged");
    }
}
