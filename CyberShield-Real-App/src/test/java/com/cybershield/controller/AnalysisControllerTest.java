package com.cybershield.controller;

import com.cybershield.model.Analysis;
import com.cybershield.model.User;
import com.cybershield.repo.AnalysisRepository;
import com.cybershield.service.AnalysisService;
import com.cybershield.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class AnalysisControllerTest {
    @Mock
    private AuthService auth;
    @Mock
    private AnalysisService analysisService;
    @Mock
    private AnalysisRepository repository;

    private AnalysisController controller;
    private User user;

    @BeforeEach
    void setUp() {
        controller = new AnalysisController(auth, analysisService, repository);
        user = mock(User.class);
        when(user.getId()).thenReturn(7L);
        when(auth.user("token")).thenReturn(user);
    }

    @Test
    void analyzeUsesAuthenticatedUserAndForwardsRequest() {
        Analysis expected = new Analysis();
        AnalysisController.Request request = new AnalysisController.Request("message", "Check this");
        when(analysisService.analyze(7L, "message", "Check this")).thenReturn(expected);

        Analysis result = controller.analyze("token", request);

        assertEquals(expected, result);
        verify(analysisService).analyze(7L, "message", "Check this");
    }

    @Test
    void historyReturnsAuthenticatedUsersRecentAnalyses() {
        List<Analysis> expected = List.of(new Analysis());
        when(repository.findTop20ByUserIdOrderByCreatedAtDesc(7L)).thenReturn(expected);

        assertEquals(expected, controller.history("token"));
    }

    @Test
    void statsCountsHighRiskItemsAndReportsTotalAndRecentCounts() {
        Analysis highRisk = new Analysis();
        highRisk.setRisk("HIGH");
        Analysis lowRisk = new Analysis();
        lowRisk.setRisk("LOW");
        when(repository.findTop20ByUserIdOrderByCreatedAtDesc(7L)).thenReturn(List.of(highRisk, lowRisk));
        when(repository.countByUserId(7L)).thenReturn(9L);

        Map<String, Object> result = controller.stats("token");

        assertEquals(9L, result.get("total"));
        assertEquals(1L, result.get("high"));
        assertEquals(2, result.get("recent"));
    }
}
