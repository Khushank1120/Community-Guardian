package com.communityguardian.model;

public class Incident {
    public String id;
    public String title;
    public String category;
    public String severity;
    public String location;
    public String details;
    public boolean verified;
    public String status;
    public String sourceType;
    public int corroborationCount;
    public double confidenceScore;
    public boolean needsReview;
    public String expiresAt;
    public String reportedAt;
    public String clusterId;

    public String toDisplayString() {
        return String.format(
            "id=%s | title=%s | category=%s | severity=%s | location=%s | source=%s | corroboration=%d | confidence=%.2f | needsReview=%s | verified=%s | status=%s | expiresAt=%s | reportedAt=%s | cluster=%s | details=%s",
            id, title, category, severity, location, sourceType, corroborationCount, confidenceScore, needsReview, verified, status, expiresAt, reportedAt, clusterId, details
        );
    }

    public String toJson() {
        return "{"
            + "\"id\":\"" + esc(id) + "\","
            + "\"title\":\"" + esc(title) + "\","
            + "\"category\":\"" + esc(category) + "\","
            + "\"severity\":\"" + esc(severity) + "\","
            + "\"location\":\"" + esc(location) + "\","
            + "\"sourceType\":\"" + esc(sourceType) + "\","
            + "\"corroborationCount\":" + corroborationCount + ","
            + "\"confidenceScore\":" + String.format(java.util.Locale.US, "%.4f", confidenceScore) + ","
            + "\"needsReview\":" + needsReview + ","
            + "\"verified\":" + verified + ","
            + "\"status\":\"" + esc(status) + "\","
            + "\"expiresAt\":\"" + esc(expiresAt) + "\","
            + "\"reportedAt\":\"" + esc(reportedAt) + "\","
            + "\"clusterId\":\"" + esc(clusterId) + "\","
            + "\"details\":\"" + esc(details) + "\""
            + "}";
    }

    private static String esc(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
