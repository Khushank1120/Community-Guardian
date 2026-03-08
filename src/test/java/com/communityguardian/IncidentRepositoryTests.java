package com.communityguardian;

import com.communityguardian.model.Incident;
import com.communityguardian.repository.IncidentRepository;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class IncidentRepositoryTests {
    public static void runAll() throws IOException {
        testCreateAndFindById();
        testPruneExpired();
        testLocationEncryptedAtRest();
    }

    static void testCreateAndFindById() throws IOException {
        Path tmp = Files.createTempFile("repo", ".csv");
        try {
            IncidentRepository.initDb(Path.of("data", "sample_incidents.csv"), tmp);
            Incident in = IncidentRepository.create(
                tmp,
                "Router misconfiguration",
                "digital",
                "medium",
                "Brooklyn",
                "Multiple households left default admin credentials enabled.",
                false,
                "community",
                2,
                7,
                false
            );

            Incident found = IncidentRepository.findById(tmp, in.id);
            TestAssertions.assertEquals(in.id, found.id, "findById should return same incident");
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    static void testPruneExpired() throws IOException {
        Path tmp = Files.createTempFile("repo", ".csv");
        try {
            IncidentRepository.initDb(Path.of("data", "sample_incidents.csv"), tmp);
            List<Incident> incidents = IncidentRepository.load(tmp);
            incidents.get(0).expiresAt = "2020-01-01T00:00:00Z";
            IncidentRepository.save(tmp, incidents);

            int removed = IncidentRepository.pruneExpired(tmp);
            TestAssertions.assertTrue(removed >= 1, "expected at least one expired incident to be removed");
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    static void testLocationEncryptedAtRest() throws IOException {
        Path tmp = Files.createTempFile("repo", ".csv");
        try {
            IncidentRepository.initDb(Path.of("data", "sample_incidents.csv"), tmp);
            Incident created = IncidentRepository.create(
                tmp,
                "Suspicious network scanning",
                "digital",
                "medium",
                "Brooklyn",
                "Multiple home users reported suspicious repeated login probes overnight.",
                false,
                "community",
                1,
                7,
                false
            );

            String rawCsv = Files.readString(tmp, StandardCharsets.UTF_8);
            TestAssertions.assertTrue(!rawCsv.contains("Brooklyn"), "plaintext location should not appear at rest");

            Incident fetched = IncidentRepository.findById(tmp, created.id);
            TestAssertions.assertEquals("Brooklyn", fetched.location, "location should decrypt correctly on read");
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
