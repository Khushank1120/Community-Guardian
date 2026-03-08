package com.communityguardian.service;

import com.communityguardian.model.Incident;
import com.communityguardian.repository.IncidentRepository;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class DigestService {
    public static class DigestOptions {
        public String location;
        public String category;
        public String severity;
        public String period = "daily";
        public boolean includeUnverified = true;
        public boolean forceFallback;
    }

    public static class DigestResult {
        public final String mode;
        public final String text;

        public DigestResult(String mode, String text) {
            this.mode = mode;
            this.text = text;
        }
    }

    public static DigestResult digest(List<Incident> incidents, DigestOptions options) {
        List<Incident> scoped = applyFilters(incidents, options);

        if (scoped.isEmpty()) {
            return new DigestResult("none", "No matching incidents found.");
        }

        if (options.forceFallback) {
            return new DigestResult("fallback", summarizeWithRules(scoped, options.period));
        }

        try {
            String text = summarizeWithAI(scoped, options.period);
            return new DigestResult("ai", text);
        } catch (Exception ex) {
            String message = ex.getMessage() == null ? "" : ex.getMessage();
            if (message.contains("OpenAI quota exceeded")) {
                System.err.println("AI notice: OpenAI quota/rate limit exceeded for this key. Check billing/limits or retry later.");
            }
            if ("true".equalsIgnoreCase(System.getenv().getOrDefault("AI_DEBUG", "false"))) {
                System.err.println("AI fallback reason: " + ex.getClass().getSimpleName() + ": " + ex.getMessage());
            }
            return new DigestResult("fallback", summarizeWithRules(scoped, options.period));
        }
    }

    private static List<Incident> applyFilters(List<Incident> incidents, DigestOptions options) {
        Instant since = switch (options.period) {
            case "weekly" -> Instant.now().minus(7, ChronoUnit.DAYS);
            case "monthly" -> Instant.now().minus(30, ChronoUnit.DAYS);
            default -> Instant.now().minus(1, ChronoUnit.DAYS);
        };

        return incidents.stream()
            .filter(i -> !IncidentRepository.isExpired(i))
            .filter(i -> {
                try {
                    return Instant.parse(i.reportedAt).isAfter(since);
                } catch (Exception ex) {
                    return true;
                }
            })
            .filter(i -> options.location == null || options.location.isBlank() || i.location.equalsIgnoreCase(options.location))
            .filter(i -> options.category == null || options.category.isBlank() || i.category.equals(options.category))
            .filter(i -> options.severity == null || options.severity.isBlank() || i.severity.equals(options.severity))
            .filter(i -> options.includeUnverified || i.verified)
            .collect(Collectors.toList());
    }

    private static String summarizeWithAI(List<Incident> incidents, String period) throws IOException, InterruptedException {
        String apiKey = System.getenv("OPENAI_API_KEY");
        if (apiKey == null || apiKey.isBlank()) {
            throw new IOException("OPENAI_API_KEY missing");
        }

        String model = System.getenv().getOrDefault("OPENAI_MODEL", "gpt-4.1-mini");
        String incidentText = incidents.stream()
            .map(i -> String.format("[%s|%s|%s|confidence=%.2f|verified=%s] %s - %s", i.category, i.severity, i.location, i.confidenceScore, i.verified, i.title, i.details))
            .collect(Collectors.joining("\\n"));

        String prompt = "Create a calm " + period + " community safety digest in under 170 words with exactly 3 numbered next steps. Avoid panic language. Clearly separate verified updates from unverified local signals. Incidents: " + incidentText;
        String body = "{" +
            "\"model\":\"" + jsonEscape(model) + "\"," +
            "\"temperature\":0.2," +
            "\"messages\":[{" +
            "\"role\":\"user\"," +
            "\"content\":\"" + jsonEscape(prompt) + "\"" +
            "}]" +
            "}";

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://api.openai.com/v1/chat/completions"))
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer " + apiKey)
            .timeout(Duration.ofSeconds(10))
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();

        HttpClient client = HttpClient.newHttpClient();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() / 100 != 2) {
            String bodySnippet = response.body() == null ? "" : response.body();
            if (response.statusCode() == 429) {
                throw new IOException("OpenAI quota exceeded.");
            }
            if (bodySnippet.length() > 300) {
                bodySnippet = bodySnippet.substring(0, 300) + "...";
            }
            throw new IOException("AI call failed: HTTP " + response.statusCode() + " body=" + bodySnippet);
        }

        String content = extractOpenAIContent(response.body());
        if (content == null || content.isBlank()) {
            throw new IOException("AI response parsing failed");
        }
        return content;
    }

    private static String extractOpenAIContent(String json) {
        int idx = json.indexOf("\"content\":");
        if (idx < 0) {
            return null;
        }
        int start = json.indexOf('"', idx + 10);
        if (start < 0) {
            return null;
        }
        StringBuilder out = new StringBuilder();
        boolean escaped = false;
        for (int i = start + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (escaped) {
                switch (c) {
                    case 'n' -> out.append('\n');
                    case '"' -> out.append('"');
                    case '\\' -> out.append('\\');
                    default -> out.append(c);
                }
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '"') {
                break;
            }
            out.append(c);
        }
        return out.toString().trim();
    }

    private static String summarizeWithRules(List<Incident> incidents, String period) {
        long total = incidents.size();
        long digital = incidents.stream().filter(i -> i.category.equals("digital")).count();
        long physical = incidents.stream().filter(i -> i.category.equals("physical")).count();
        long high = incidents.stream().filter(i -> i.severity.equals("high")).count();
        long verified = incidents.stream().filter(i -> i.verified).count();

        Map<String, Long> clusters = incidents.stream()
            .collect(Collectors.groupingBy(i -> i.clusterId, LinkedHashMap::new, Collectors.counting()));
        long noisyDuplicates = clusters.values().stream().filter(c -> c > 1).count();

        return String.join("\n",
            "Community Guardian Digest (Fallback Mode)",
            "Period: " + period,
            String.format("Relevant reports: %d (%d physical, %d digital).", total, physical, digital),
            "Verified reports: " + verified + ". High-priority incidents: " + high + ".",
            "Noise reduced by clustering similar reports: " + noisyDuplicates + " repeated clusters.",
            "Next steps:",
            "1) Verify sources before forwarding alerts.",
            "2) For digital threats, enable MFA and rotate key passwords.",
            "3) For local physical risks, check in with trusted contacts and follow local advisories."
        );
    }

    private static String jsonEscape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
