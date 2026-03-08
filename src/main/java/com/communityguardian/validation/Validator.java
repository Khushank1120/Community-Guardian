package com.communityguardian.validation;

import com.communityguardian.exception.ValidationException;

import java.util.Set;

public class Validator {
    public static final Set<String> ALLOWED_CATEGORIES = Set.of("physical", "digital");
    public static final Set<String> ALLOWED_SEVERITIES = Set.of("low", "medium", "high");
    public static final Set<String> ALLOWED_STATUS = Set.of("open", "monitoring", "resolved");
    public static final Set<String> ALLOWED_SOURCE_TYPES = Set.of("community", "official", "news", "sensor", "unknown");

    public static void validateCreateInput(String title, String category, String severity, String location, String details, String sourceType, int corroborationCount) {
        if (title == null || title.trim().isEmpty()) {
            throw new ValidationException("title is required");
        }
        if (!ALLOWED_CATEGORIES.contains(category)) {
            throw new ValidationException("category must be one of " + ALLOWED_CATEGORIES);
        }
        if (!ALLOWED_SEVERITIES.contains(severity)) {
            throw new ValidationException("severity must be one of " + ALLOWED_SEVERITIES);
        }
        if (location == null || location.trim().isEmpty()) {
            throw new ValidationException("location is required");
        }
        if (details == null || details.trim().length() < 10) {
            throw new ValidationException("details must be at least 10 characters");
        }
        if (!ALLOWED_SOURCE_TYPES.contains(sourceType)) {
            throw new ValidationException("source-type must be one of " + ALLOWED_SOURCE_TYPES);
        }
        if (corroborationCount < 0) {
            throw new ValidationException("corroboration-count must be >= 0");
        }
    }

    public static void validateStatus(String status) {
        if (status != null && !ALLOWED_STATUS.contains(status)) {
            throw new ValidationException("status must be one of " + ALLOWED_STATUS);
        }
    }
}
