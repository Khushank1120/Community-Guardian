package com.communityguardian.cli;

import com.communityguardian.model.Incident;
import com.communityguardian.service.DigestService;
import com.communityguardian.service.ReportInsightsService;
import com.communityguardian.service.SafeCircleService;

import java.util.List;
import java.util.Locale;

public class OutputFormatter {
    public static String formatInitPretty(String dbPath) {
        return "Community Guardian\n"
            + "Status  : Database initialized\n"
            + "DB Path : " + dbPath;
    }

    public static String formatIncidentPretty(Incident in) {
        StringBuilder sb = new StringBuilder();
        sb.append("Incident\n");
        sb.append("  ID            : ").append(in.id).append("\n");
        sb.append("  Title         : ").append(in.title).append("\n");
        sb.append("  Category      : ").append(in.category).append("\n");
        sb.append("  Severity      : ").append(in.severity).append("\n");
        sb.append("  Location      : ").append(in.location).append("\n");
        sb.append("  Source        : ").append(in.sourceType).append("\n");
        sb.append("  Corroboration : ").append(in.corroborationCount).append(" (validated)\n");
        sb.append("  Confidence    : ").append(String.format(java.util.Locale.US, "%.2f", in.confidenceScore)).append("\n");
        sb.append("  Needs Review  : ").append(in.needsReview).append("\n");
        sb.append("  Verified      : ").append(in.verified).append("\n");
        sb.append("  Status        : ").append(in.status).append("\n");
        sb.append("  Expires At    : ").append(in.expiresAt).append("\n");
        sb.append("  Reported At   : ").append(in.reportedAt).append("\n");
        sb.append("  Cluster       : ").append(in.clusterId).append("\n");
        sb.append("  Details       : ").append(in.details);
        return sb.toString();
    }

    public static String formatIncidentListPretty(List<Incident> incidents) {
        if (incidents.isEmpty()) {
            return "No incidents found.";
        }

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%-8s %-10s %-8s %-10s %-8s %-7s %-11s %-36s %-24s %s%n",
            "Type", "Location", "Severity", "Status", "Review", "Verify", "Confidence", "ID", "Title", "Cluster"));
        sb.append("-------------------------------------------------------------------------------------------------------------------------------------------------------------\n");

        for (Incident i : incidents) {
            sb.append(String.format("%-8s %-10s %-8s %-10s %-8s %-7s %-11s %-36s %-24s %s%n",
                truncate(i.category, 8),
                truncate(i.location, 10),
                truncate(i.severity, 8),
                truncate(i.status, 10),
                i.needsReview,
                i.verified,
                String.format(java.util.Locale.US, "%.2f", i.confidenceScore),
                truncate(i.id, 36),
                truncate(i.title, 24),
                truncate(i.clusterId, 36)
            ));
        }

        sb.append("\nTotal incidents: ").append(incidents.size());
        return sb.toString();
    }

    public static String formatDigestPretty(DigestService.DigestResult result) {
        return "Digest\n"
            + "  Mode : " + result.mode + "\n"
            + "  ----\n"
            + indent(result.text, "  ");
    }

    public static String formatChecklistPretty(Incident incident, String scope, List<String> steps) {
        StringBuilder sb = new StringBuilder();
        sb.append("Checklist\n");
        sb.append("  Incident ID : ").append(incident.id).append("\n");
        sb.append("  Title       : ").append(incident.title).append("\n");
        sb.append("  Scope       : ").append(scope).append("\n");
        sb.append("  ---\n");
        for (int i = 0; i < steps.size(); i++) {
            sb.append("  ").append(i + 1).append(") ").append(steps.get(i)).append("\n");
        }
        return sb.toString().trim();
    }

    public static String formatClustersPretty(List<ReportInsightsService.ClusterSummary> clusters) {
        if (clusters.isEmpty()) {
            return "No clusters found.";
        }
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%-6s %-10s %-9s %-11s %-9s %-12s %-30s %s%n",
            "Count", "Location", "Category", "AvgConf", "Verified", "Scope", "Sample Title", "Cluster ID"));
        sb.append("---------------------------------------------------------------------------------------------------------------------------------\n");
        for (ReportInsightsService.ClusterSummary c : clusters) {
            sb.append(String.format(Locale.US, "%-6d %-10s %-9s %-11.2f %-9d %-12s %-30s %s%n",
                c.count, truncate(c.location, 10), truncate(c.category, 9), c.avgConfidence, c.verifiedCount, truncate(c.scope, 12),
                truncate(c.sampleTitle, 30), truncate(c.clusterId, 40)));
        }
        return sb.toString().trim();
    }

    public static String formatSafeStatusesPretty(List<SafeCircleService.StatusUpdate> updates) {
        if (updates.isEmpty()) {
            return "No safe-circle updates found.";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Safe Circle Updates\n");
        for (SafeCircleService.StatusUpdate s : updates) {
            sb.append("  [").append(s.createdAt).append("] ").append(s.sender).append(": ").append(s.message).append("\n");
        }
        return sb.toString().trim();
    }

    private static String truncate(String value, int maxLen) {
        if (value == null) {
            return "";
        }
        if (value.length() <= maxLen) {
            return value;
        }
        if (maxLen <= 3) {
            return value.substring(0, maxLen);
        }
        return value.substring(0, maxLen - 3) + "...";
    }

    private static String indent(String value, String prefix) {
        String[] lines = (value == null ? "" : value).split("\\n", -1);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            if (i > 0) {
                sb.append("\n");
            }
            sb.append(prefix).append(lines[i]);
        }
        return sb.toString();
    }
}
