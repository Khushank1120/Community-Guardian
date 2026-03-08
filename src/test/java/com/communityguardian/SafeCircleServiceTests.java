package com.communityguardian;

import com.communityguardian.exception.ValidationException;
import com.communityguardian.service.SafeCircleService;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class SafeCircleServiceTests {
    public static void runAll() throws IOException {
        testShareAndViewStatus();
        testWrongPassphraseFails();
        testOwnerCanGrantAndManagerCanAddRemove();
    }

    static void testShareAndViewStatus() throws IOException {
        Path tmp = Files.createTempFile("safe", ".csv");
        Path members = Files.createTempFile("members", ".csv");
        try {
            SafeCircleService.createCircle(members, "family", "alice");
            SafeCircleService.addMember(members, "family", "alice", "bob");
            SafeCircleService.shareStatus(tmp, members, "family", "alice", "alice", "Reached home safely", "strongpass123");
            List<SafeCircleService.StatusUpdate> updates = SafeCircleService.viewStatus(tmp, members, "family", "bob", "strongpass123");
            TestAssertions.assertTrue(updates.size() == 1, "one update expected");
            TestAssertions.assertTrue(updates.get(0).message.contains("Reached home"), "decrypted message mismatch");
        } finally {
            Files.deleteIfExists(tmp);
            Files.deleteIfExists(members);
        }
    }

    static void testWrongPassphraseFails() throws IOException {
        Path tmp = Files.createTempFile("safe", ".csv");
        Path members = Files.createTempFile("members", ".csv");
        try {
            SafeCircleService.createCircle(members, "family", "alice");
            SafeCircleService.shareStatus(tmp, members, "family", "alice", "alice", "Reached home safely", "strongpass123");
            boolean threw = false;
            try {
                SafeCircleService.viewStatus(tmp, members, "family", "alice", "wrongpass123");
            } catch (ValidationException ex) {
                threw = true;
            }
            TestAssertions.assertTrue(threw, "wrong passphrase should fail");
        } finally {
            Files.deleteIfExists(tmp);
            Files.deleteIfExists(members);
        }
    }

    static void testOwnerCanGrantAndManagerCanAddRemove() throws IOException {
        Path tmp = Files.createTempFile("safe", ".csv");
        Path members = Files.createTempFile("members", ".csv");
        try {
            SafeCircleService.createCircle(members, "family", "owner");
            SafeCircleService.addMember(members, "family", "owner", "manager1");

            boolean deniedGrantByNonOwner = false;
            try {
                SafeCircleService.setManageAccess(members, "family", "manager1", "manager1", true);
            } catch (ValidationException ex) {
                deniedGrantByNonOwner = true;
            }
            TestAssertions.assertTrue(deniedGrantByNonOwner, "non-owner should not grant manage access");

            SafeCircleService.setManageAccess(members, "family", "owner", "manager1", true);
            SafeCircleService.addMember(members, "family", "manager1", "member2");

            List<SafeCircleService.MemberEntry> membersList = SafeCircleService.listMembers(members, "family", "owner");
            boolean managerCanManage = membersList.stream().anyMatch(m -> m.member.equals("manager1") && m.canManage);
            TestAssertions.assertTrue(managerCanManage, "manager1 should have manage access");

            SafeCircleService.removeMember(members, "family", "manager1", "member2");
            List<SafeCircleService.MemberEntry> after = SafeCircleService.listMembers(members, "family", "owner");
            boolean memberStillActive = after.stream().anyMatch(m -> m.member.equals("member2"));
            TestAssertions.assertTrue(!memberStillActive, "member2 should be removed by delegated manager");
        } finally {
            Files.deleteIfExists(tmp);
            Files.deleteIfExists(members);
        }
    }
}
