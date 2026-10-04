package com.cybershield.service;

import com.cybershield.model.Analysis;
import com.cybershield.repo.AnalysisRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AnalysisServiceTest {
    @Mock
    private AnalysisRepository repository;

    @InjectMocks
    private AnalysisService service;

    @Test
    void analyzeStoresLowRiskWhenNoIndicatorsArePresent() {
        when(repository.save(any(Analysis.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Analysis result = service.analyze(12L, "message", "Your parcel status is ready.");

        assertEquals(12L, result.getUserId());
        assertEquals("message", result.getType());
        assertEquals(0, result.getScore());
        assertEquals("LOW", result.getRisk());
        assertTrue(result.getReasons().contains("No strong scam indicators"));
        verify(repository).save(result);
    }

    @Test
    void analyzeAddsUrgencyAndSensitiveInformationReasons() {
        when(repository.save(any(Analysis.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Analysis result = service.analyze(1L, "message", "URGENT: provide your OTP immediately");

        assertEquals(50, result.getScore());
        assertEquals("MEDIUM", result.getRisk());
        assertTrue(result.getReasons().contains("Uses pressure or urgency: urgent"));
        assertTrue(result.getReasons().contains("Requests sensitive information: otp"));
    }

    @Test
    void analyzeAddsExternalAndShortenedLinkRisk() {
        when(repository.save(any(Analysis.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Analysis result = service.analyze(2L, "link", "Review https://bit.ly/account");

        assertEquals(30, result.getScore());
        assertEquals("MEDIUM", result.getRisk());
        assertTrue(result.getReasons().contains("Contains an external link"));
        assertTrue(result.getReasons().contains("Uses a shortened link"));
    }

    @Test
    void analyzeCapsScoreAtOneHundred() {
        when(repository.save(any(Analysis.class))).thenAnswer(invocation -> invocation.getArgument(0));
        String input = "urgent immediately act now within 24 hours last warning otp pin cvv password kyc bank account "
                + "upi pin verification code pay now send money refund prize lottery cashback fee payment "
                + "https://example.com bit.ly tinyurl t.co";

        Analysis result = service.analyze(3L, "message", input);

        assertEquals(100, result.getScore());
        assertEquals("HIGH", result.getRisk());
    }

    @Test
    void analyzeTreatsNullInputAsEmptyText() {
        when(repository.save(any(Analysis.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Analysis result = service.analyze(4L, "message", null);

        assertEquals("", result.getInputText());
        assertEquals(0, result.getScore());
        assertEquals("LOW", result.getRisk());
    }
}
