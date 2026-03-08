package com.communityguardian.service;

import com.communityguardian.model.Incident;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

public class ReportInsightsService {
    public static class ClusterSummary {
        public String clusterId;
        public int count;
        public String category;
        public String location;
        public double avgConfidence;
        public int verifiedCount;
        public String scope;
        public String sampleTitle;
    }

    public static String classifyScope(Incident in) {
        boolean institutionalSource = "official".equals(in.sourceType) || "news".equals(in.sourceType) || "sensor".equals(in.sourceType);
        if (institutionalSource && in.corroborationCount >= 2) {
            return "widespread";
        }
        if (in.corroborationCount >= 2 || in.confidenceScore >= 0.70) {
            return "local-emerging";
        }
        return "local-unverified";
    }

    public static List<String> checklist(Incident in) {
        String txt = (in.title + " " + in.details).toLowerCase(Locale.US);
        List<String> out = new ArrayList<>();

        if ("digital".equals(in.category)) {
            if (txt.contains("phish") || txt.contains("credential") || txt.contains("password")) {
                out.add("Do not click links in unsolicited messages; verify sender through an official channel.");
                out.add("Enable MFA on email and banking accounts, then rotate reused passwords.");
                out.add("Report suspicious messages to local admin/IT and alert your safe circle.");
                return out;
            }
            if (txt.contains("breach") || txt.contains("leak") || txt.contains("data")) {
                out.add("Change passwords for affected services immediately.");
                out.add("Review account login history and enable MFA.");
                out.add("Freeze credit monitoring if personal identifiers were exposed.");
                return out;
            }
            out.add("Confirm threat details via at least one trusted source.");
            out.add("Harden core accounts: MFA, password updates, recovery options.");
            out.add("Share a short, verified warning with close contacts.");
            return out;
        }

        if (txt.contains("theft") || txt.contains("break") || txt.contains("suspicious")) {
            out.add("Avoid solo travel in the affected area until risk decreases.");
            out.add("Coordinate neighborhood check-ins and report incidents quickly.");
            out.add("Capture only factual details (time/place), avoid rumor-forwarding.");
            return out;
        }

        out.add("Follow official local advisories for affected zones.");
        out.add("Use practical precautions (lighting, route changes, buddy system).");
        out.add("Share verified updates with your trusted contacts.");
        return out;
    }

    public static List<ClusterSummary> clusterSummaries(List<Incident> incidents) {
        Map<String, List<Incident>> grouped = incidents.stream().collect(Collectors.groupingBy(i -> i.clusterId));
        return grouped.entrySet().stream().map(entry -> {
            List<Incident> group = entry.getValue();
            ClusterSummary cs = new ClusterSummary();
            cs.clusterId = entry.getKey();
            cs.count = group.size();
            Incident first = group.get(0);
            cs.category = first.category;
            cs.location = first.location;
            cs.avgConfidence = group.stream().mapToDouble(i -> i.confidenceScore).average().orElse(0.0);
            cs.verifiedCount = (int) group.stream().filter(i -> i.verified).count();
            cs.scope = classifyScope(group.stream().max((a, b) -> Double.compare(a.confidenceScore, b.confidenceScore)).orElse(first));
            cs.sampleTitle = first.title;
            return cs;
        }).sorted((a, b) -> Integer.compare(b.count, a.count)).collect(Collectors.toList());
    }
}
