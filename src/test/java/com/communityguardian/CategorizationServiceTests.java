package com.communityguardian;

import com.communityguardian.service.CategorizationService;

public class CategorizationServiceTests {
    public static void runAll() {
        testRuleFallbackPhishingToDigital();
        testRuleFallbackPackageTheftToPhysical();
        testExplicitCategoryWins();
    }

    private static void testRuleFallbackPhishingToDigital() {
        String category = CategorizationService.resolveCategory(
            "auto",
            "Suspicious QR phishing flyers",
            "Residents reported QR stickers linking to credential-harvest pages."
        );
        TestAssertions.assertTrue("digital".equals(category), "phishing should map to digital");
    }

    private static void testRuleFallbackPackageTheftToPhysical() {
        String category = CategorizationService.resolveCategory(
            "auto",
            "Repeated package theft near apartment blocks",
            "Porch theft reports increased on two nearby streets this week."
        );
        TestAssertions.assertTrue("physical".equals(category), "package theft should map to physical");
    }

    private static void testExplicitCategoryWins() {
        String category = CategorizationService.resolveCategory(
            "digital",
            "Streetlight outage",
            "Three blocks are dark after dusk."
        );
        TestAssertions.assertTrue("digital".equals(category), "explicit category should be preserved");
    }
}
