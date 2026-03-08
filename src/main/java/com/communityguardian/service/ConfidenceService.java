package com.communityguardian.service;

import com.communityguardian.model.Incident;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Locale;

public class ConfidenceService {
    private static final double DEFAULT_REVIEW_THRESHOLD = 0.60;

    public static double computeRuleScore(Incident in) {
        double base = switch (in.sourceType) {
            case "official" -> 0.85;
            case "news" -> 0.75;
            case "sensor" -> 0.72;
            case "community" -> 0.55;
            default -> 0.40;
        };

        double corroborationBoost = Math.min(in.corroborationCount, 3) * 0.07;
        double verifiedBoost = in.verified ? 0.08 : 0.0;
        double severityAdjustment = switch (in.severity) {
            case "high" -> -0.05;
            case "low" -> 0.03;
            default -> 0.0;
        };
        double detailBoost = in.details != null && in.details.length() > 80 ? 0.03 : 0.0;

        return clamp(base + corroborationBoost + verifiedBoost + severityAdjustment + detailBoost, 0.05, 0.99);
    }

    public static double maybeAdjustWithAI(Incident in, double ruleScore, boolean aiAdjust) {
        if (!aiAdjust) {
            return ruleScore;
        }

        try {
            Double aiScore = scoreWithOpenAI(in);
            if (aiScore == null) {
                return ruleScore;
            }
            return clamp((0.7 * ruleScore) + (0.3 * aiScore), 0.05, 0.99);
        } catch (Exception ex) {
            if ("true".equalsIgnoreCase(System.getenv().getOrDefault("AI_DEBUG", "false"))) {
                System.err.println("AI confidence adjustment skipped: " + ex.getMessage());
            }
            return ruleScore;
        }
    }

    public static boolean shouldFlagForReview(Incident in) {
        if (in.verified) {
            return false;
        }
        double threshold = parseDoubleOrDefault(System.getenv("CONFIDENCE_REVIEW_THRESHOLD"), DEFAULT_REVIEW_THRESHOLD);
        return in.confidenceScore < threshold;
    }

    private static Double scoreWithOpenAI(Incident in) throws IOException, InterruptedException {
        String apiKey = System.getenv("OPENAI_API_KEY");
        if (apiKey == null || apiKey.isBlank()) {
            return null;
        }

        String model = System.getenv().getOrDefault("OPENAI_MODEL", "gpt-4.1-mini");
        String prompt = String.format(
            Locale.US,
            "Return only a number between 0.0 and 1.0 for report credibility. No words. Data: title=%s; category=%s; severity=%s; location=%s; source=%s; corroboration=%d; verified=%s; details=%s",
            in.title, in.category, in.severity, in.location, in.sourceType, in.corroborationCount, in.verified, in.details
        );

        String body = "{" +
            "\"model\":\"" + jsonEscape(model) + "\"," +
            "\"temperature\":0.0," +
            "\"messages\":[{" +
            "\"role\":\"user\"," +
            "\"content\":\"" + jsonEscape(prompt) + "\"" +
            "}]" +
            "}";

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://api.openai.com/v1/chat/completions"))
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer " + apiKey)
            .timeout(Duration.ofSeconds(8))
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();

        HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() / 100 != 2) {
            return null;
        }

        String content = extractContent(response.body());
        if (content == null || content.isBlank()) {
            return null;
        }

        Double parsed = extractFirstNumber(content);
        if (parsed == null) {
            return null;
        }
        return clamp(parsed, 0.0, 1.0);
    }

    private static String extractContent(String json) {
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

    private static Double extractFirstNumber(String value) {
        StringBuilder num = new StringBuilder();
        boolean seenDigit = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if ((c >= '0' && c <= '9') || c == '.') {
                num.append(c);
                seenDigit = true;
            } else if (seenDigit) {
                break;
            }
        }
        if (num.isEmpty()) {
            return null;
        }
        try {
            return Double.parseDouble(num.toString());
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    private static String jsonEscape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

    private static double clamp(double value, double min, double max) {
        return Math.max(min, Math.min(max, value));
    }

    private static double parseDoubleOrDefault(String raw, double fallback) {
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        try {
            return Double.parseDouble(raw);
        } catch (NumberFormatException ex) {
            return fallback;
        }
    }
}
