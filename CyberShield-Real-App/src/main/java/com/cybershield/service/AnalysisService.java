package com.cybershield.service;

import com.cybershield.model.Analysis;
import com.cybershield.repo.AnalysisRepository;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class AnalysisService {

    private final AnalysisRepository repo;

    public AnalysisService(AnalysisRepository repo) {
        this.repo = repo;
    }

    public Analysis analyze(Long userId, String type, String input) {

        String text = input == null ? "" : input;
        String normalizedText = text.toLowerCase();

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // =========================
        // 1. URGENCY ANALYSIS
        // =========================

        String[] urgencyIndicators = {
                "urgent",
                "immediately",
                "act now",
                "within 24 hours",
                "within 10 minutes",
                "within 5 minutes",
                "last warning",
                "expires today",
                "do not delay"
        };

        for (String indicator : urgencyIndicators) {
            if (normalizedText.contains(indicator)) {
                score += 12;
                reasons.add("Pressure or urgency detected: " + indicator);
            }
        }

        // =========================
        // 2. SENSITIVE INFORMATION
        // =========================

        String[] sensitiveInformationIndicators = {
                "otp",
                "one time password",
                "pin",
                "cvv",
                "password",
                "kyc",
                "bank account",
                "upi pin",
                "verification code"
        };

        for (String indicator : sensitiveInformationIndicators) {
            if (normalizedText.contains(indicator)) {
                score += 20;
                reasons.add("Sensitive information request detected: " + indicator);
            }
        }

        // =========================
        // 3. PAYMENT / REWARD CONTEXT
        // =========================

        String[] suspiciousPaymentIndicators = {
                "pay now",
                "send money",
                "claim refund",
                "prize",
                "lottery",
                "cashback",
                "processing fee",
                "registration fee",
                "payment required",
                "payment request"
        };

        for (String indicator : suspiciousPaymentIndicators) {
            if (normalizedText.contains(indicator)) {
                score += 10;
                reasons.add("Suspicious payment/reward context: " + indicator);
            }
        }

        // =========================
        // 4. TRANSACTION AMOUNT
        // =========================

        Pattern amountPattern = Pattern.compile(
                "(?:₹|rs\\.?|inr)\\s*([0-9,]+(?:\\.\\d+)?)",
                Pattern.CASE_INSENSITIVE
        );

        Matcher amountMatcher = amountPattern.matcher(normalizedText);

        if (amountMatcher.find()) {

            String amountText = amountMatcher.group(1).replace(",", "");

            try {
                double amount = Double.parseDouble(amountText);

                if (amount >= 100000) {
                    score += 25;
                    reasons.add("Very high transaction amount detected: ₹" + amountText);
                } else if (amount >= 50000) {
                    score += 18;
                    reasons.add("High transaction amount detected: ₹" + amountText);
                } else if (amount >= 20000) {
                    score += 10;
                    reasons.add("Moderately high transaction amount detected: ₹" + amountText);
                }

            } catch (NumberFormatException ignored) {
                // Ignore invalid amount format
            }
        }

        // =========================
        // 5. UNKNOWN RECIPIENT
        // =========================

        if (normalizedText.contains("unknown merchant")
                || normalizedText.contains("unknown recipient")
                || normalizedText.contains("unknown beneficiary")
                || normalizedText.contains("unverified recipient")) {

            score += 20;
            reasons.add("Unknown or unverified recipient detected.");
        }

        // =========================
        // 6. DEVICE ANALYSIS
        // =========================

        if (normalizedText.contains("new device")
                || normalizedText.contains("unknown device")
                || normalizedText.contains("unrecognized device")) {

            score += 15;
            reasons.add("Transaction initiated from an unrecognized device.");
        }

        if (normalizedText.contains("registered device")
                || normalizedText.contains("trusted device")
                || normalizedText.contains("known device")) {

            score -= 5;
            reasons.add("Transaction originated from a recognized device.");
        }

        // =========================
        // 7. LOCATION ANALYSIS
        // =========================

        if (normalizedText.contains("unusual location")
                || normalizedText.contains("unknown location")
                || normalizedText.contains("different location")
                || normalizedText.contains("foreign location")) {

            score += 15;
            reasons.add("Unusual transaction location detected.");
        }

        // =========================
        // 8. TRANSACTION TIME
        // =========================

        Pattern timePattern = Pattern.compile(
                "(\\d{1,2}):(\\d{2})\\s*(am|pm)?",
                Pattern.CASE_INSENSITIVE
        );

        Matcher timeMatcher = timePattern.matcher(normalizedText);

        if (timeMatcher.find()) {

            try {
                int hour = Integer.parseInt(timeMatcher.group(1));
                String period = timeMatcher.group(3);

                if (period != null) {
                    period = period.toLowerCase();

                    if (period.equals("pm") && hour != 12) {
                        hour += 12;
                    }

                    if (period.equals("am") && hour == 12) {
                        hour = 0;
                    }
                }

                if (hour >= 0 && hour < 5) {
                    score += 15;
                    reasons.add("Transaction occurred during an unusual late-night period.");
                }

            } catch (NumberFormatException ignored) {
                // Ignore invalid time format
            }
        }

        // =========================
        // 9. TRANSACTION STATUS
        // =========================

        if (normalizedText.contains("pending")
                && (normalizedText.contains("urgent")
                || normalizedText.contains("unknown merchant")
                || normalizedText.contains("new device"))) {

            score += 10;
            reasons.add("Pending transaction combined with other risk indicators.");
        }

        // Completed transactions are not automatically considered suspicious.
        if (normalizedText.contains("completed")
                && normalizedText.contains("registered device")
                && !normalizedText.contains("urgent")
                && !normalizedText.contains("unknown merchant")) {

            score -= 5;
            reasons.add("Completed transaction from a recognized device.");
        }

        // =========================
        // 10. LINK ANALYSIS
        // =========================

        if (normalizedText.matches(".*https?://[^ ]+.*")) {

            boolean trustedDomain =
                    normalizedText.contains("google.com")
                    || normalizedText.contains("microsoft.com")
                    || normalizedText.contains("apple.com")
                    || normalizedText.contains("amazon.com")
                    || normalizedText.contains("wikipedia.org")
                    || normalizedText.contains("github.com");

            if (!trustedDomain) {
                score += 12;
                reasons.add("Contains an external link; verify the domain before opening.");
            }
        }

        // =========================
        // 11. SHORTENED LINKS
        // =========================

        if (normalizedText.contains("bit.ly")
                || normalizedText.contains("tinyurl")
                || normalizedText.contains("t.co")) {

            score += 18;
            reasons.add("Uses a shortened link that hides the destination.");
        }

        // =========================
        // 12. SCORE NORMALIZATION
        // =========================

        if (score < 0) {
            score = 0;
        }

        score = Math.min(score, 100);

        // =========================
        // 13. RISK LEVEL
        // =========================

        String risk;

        if (score >= 60) {
            risk = "HIGH";
        } else if (score >= 30) {
            risk = "MEDIUM";
        } else {
            risk = "LOW";
        }

        // =========================
        // 14. DEFAULT RESULT
        // =========================

        if (reasons.isEmpty()) {
            reasons.add(
                    "No strong scam or transaction risk indicators were detected."
            );
        }

        // =========================
        // 15. SAVE ANALYSIS
        // =========================

        Analysis analysis = new Analysis();

        analysis.setUserId(userId);
        analysis.setType(type);
        analysis.setInputText(text);
        analysis.setScore(score);
        analysis.setRisk(risk);
        analysis.setReasons(String.join("|", reasons));

        return repo.save(analysis);
    }
}