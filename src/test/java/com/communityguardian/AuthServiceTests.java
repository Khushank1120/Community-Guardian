package com.communityguardian;

import com.communityguardian.auth.AuthService;
import com.communityguardian.exception.ValidationException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class AuthServiceTests {
    public static void runAll() throws IOException {
        testDefaultUsersCanAuthenticate();
        testInvalidPasswordRejected();
        testUsersFileStoredEncrypted();
        testCreateAccountAndAuthenticate();
        testAccountLockoutAfterRepeatedFailures();
    }

    static void testDefaultUsersCanAuthenticate() throws IOException {
        Path users = Files.createTempFile("users", ".csv");
        try {
            Files.deleteIfExists(users);
            AuthService.ensureDefaultUsers(users);

            AuthService.Session user = AuthService.authenticate(users, "demo_user", "UserDemo@1234");
            TestAssertions.assertEquals("user", user.role, "demo user role mismatch");

            AuthService.Session reviewer = AuthService.authenticate(users, "demo_reviewer", "ReviewDemo@1234");
            TestAssertions.assertEquals("reviewer", reviewer.role, "demo reviewer role mismatch");
        } finally {
            Files.deleteIfExists(users);
        }
    }

    static void testInvalidPasswordRejected() throws IOException {
        Path users = Files.createTempFile("users", ".csv");
        try {
            Files.deleteIfExists(users);
            AuthService.ensureDefaultUsers(users);

            boolean threw = false;
            try {
                AuthService.authenticate(users, "demo_user", "wrong-password");
            } catch (ValidationException ex) {
                threw = true;
            }
            TestAssertions.assertTrue(threw, "invalid password should be rejected");
        } finally {
            Files.deleteIfExists(users);
        }
    }

    static void testUsersFileStoredEncrypted() throws IOException {
        Path users = Files.createTempFile("users", ".csv");
        try {
            Files.deleteIfExists(users);
            AuthService.ensureDefaultUsers(users);
            String raw = Files.readString(users, StandardCharsets.UTF_8);
            TestAssertions.assertTrue(raw.startsWith("ENCv2:") || raw.startsWith("ENCv1:"), "users file should be encrypted envelope");
            TestAssertions.assertTrue(!raw.contains("demo_user"), "plaintext username should not be visible");
        } finally {
            Files.deleteIfExists(users);
        }
    }

    static void testCreateAccountAndAuthenticate() throws IOException {
        Path users = Files.createTempFile("users", ".csv");
        try {
            Files.deleteIfExists(users);
            AuthService.ensureDefaultUsers(users);
            AuthService.createAccount(users, "new_user", "user", "NewUser@123!", "Queens");
            AuthService.Session session = AuthService.authenticate(users, "new_user", "NewUser@123!");
            TestAssertions.assertEquals("user", session.role, "created account role mismatch");
            TestAssertions.assertEquals("Queens", session.defaultLocation, "default location mismatch");
        } finally {
            Files.deleteIfExists(users);
        }
    }

    static void testAccountLockoutAfterRepeatedFailures() throws IOException {
        Path users = Files.createTempFile("users", ".csv");
        String prevMax = System.getProperty("auth.max.failed");
        String prevMins = System.getProperty("auth.lockout.minutes");
        try {
            System.setProperty("auth.max.failed", "2");
            System.setProperty("auth.lockout.minutes", "15");

            Files.deleteIfExists(users);
            AuthService.ensureDefaultUsers(users);

            boolean firstFail = false;
            try {
                AuthService.authenticate(users, "demo_user", "wrong1");
            } catch (ValidationException ex) {
                firstFail = true;
            }
            TestAssertions.assertTrue(firstFail, "first invalid login should fail");

            boolean secondFail = false;
            try {
                AuthService.authenticate(users, "demo_user", "wrong2");
            } catch (ValidationException ex) {
                secondFail = true;
            }
            TestAssertions.assertTrue(secondFail, "second invalid login should fail");

            boolean locked = false;
            try {
                AuthService.authenticate(users, "demo_user", "UserDemo@1234");
            } catch (ValidationException ex) {
                locked = ex.getMessage().toLowerCase().contains("locked");
            }
            TestAssertions.assertTrue(locked, "account should be locked after repeated failures");
        } finally {
            if (prevMax == null) {
                System.clearProperty("auth.max.failed");
            } else {
                System.setProperty("auth.max.failed", prevMax);
            }
            if (prevMins == null) {
                System.clearProperty("auth.lockout.minutes");
            } else {
                System.setProperty("auth.lockout.minutes", prevMins);
            }
            Files.deleteIfExists(users);
        }
    }
}
