package com.communityguardian.service;

import com.communityguardian.exception.ValidationException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Locale;

public class CategorizationService {
    public static String resolveCategory(String requestedCategory, String title, String details) {
        String normalizedRequest = requestedCategory == null ? "" : requestedCategory.trim().toLowerCase(Locale.ROOT);
        if (!normalizedRequest.isBlank() && !"auto".equals(normalizedRequest)) {
            if (!"digital".equals(normalizedRequest) && !"physical".equals(normalizedRequest)) {
                throw new ValidationException("category must be one of [physical, digital, auto]");
            }
            return normalizedRequest;
        }

        try {
            String aiCategory = categorizeWithAI(title, details);
            if ("digital".equals(aiCategory) || "physical".equals(aiCategory)) {
                return aiCategory;
            }
        } catch (Exception ex) {
            if ("true".equalsIgnoreCase(System.getenv().getOrDefault("AI_DEBUG", "false"))) {
                System.err.println("AI categorization skipped: " + ex.getMessage());
            }
        }

        return categorizeWithRules(title, details);
    }

    static String categorizeWithRules(String title, String details) {
        String text = ((title == null ? "" : title) + " " + (details == null ? "" : details)).toLowerCase(Locale.ROOT);

        if (containsAny(text, "phishing", "scam", "malware", "ransomware", "credential", "password", "email spoof", "qr", "breach", "data leak", "account reset")) {
            return "digital";
        }
        if (containsAny(text, "package theft", "porch pirate", "theft", "robbery", "break-in", "streetlight outage", "assault", "suspicious van", "fire", "flood")) {
            return "physical";
        }

        // Conservative default for unknown free-text local incidents.
        return "physical";
    }

    private static boolean containsAny(String text, String... tokens) {
        for (String token : tokens) {
            if (text.contains(token)) {
                return true;
            }
        }
        return false;
    }

    private static String categorizeWithAI(String title, String details) throws IOException, InterruptedException {
        String apiKey = System.getenv("OPENAI_API_KEY");
        if (apiKey == null || apiKey.isBlank()) {
            throw new IOException("OPENAI_API_KEY missing");
        }
        String model = System.getenv().getOrDefault("OPENAI_MODEL", "gpt-4.1-mini");
        String prompt = "Classify this community safety report into exactly one label: DIGITAL or PHYSICAL. "
            + "Return exactly one word only.\n"
            + "title: " + (title == null ? "" : title) + "\n"
            + "details: " + (details == null ? "" : details);

        String body = "{"
            + "\"model\":\"" + jsonEscape(model) + "\","
            + "\"temperature\":0.0,"
            + "\"messages\":[{\"role\":\"user\",\"content\":\"" + jsonEscape(prompt) + "\"}]"
            + "}";

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://api.openai.com/v1/chat/completions"))
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer " + apiKey)
            .timeout(Duration.ofSeconds(8))
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();

        HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() / 100 != 2) {
            throw new IOException("AI call failed: HTTP " + response.statusCode());
        }
        String content = extractOpenAIContent(response.body());
        if (content == null || content.isBlank()) {
            throw new IOException("AI response parsing failed");
        }
        String normalized = content.trim().toLowerCase(Locale.ROOT);
        if (normalized.contains("digital")) {
            return "digital";
        }
        if (normalized.contains("physical")) {
            return "physical";
        }
        throw new IOException("unexpected AI category response");
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

    private static String jsonEscape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
