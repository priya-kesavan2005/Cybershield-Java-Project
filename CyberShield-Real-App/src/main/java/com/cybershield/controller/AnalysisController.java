package com.cybershield.controller;
import com.cybershield.model.*; import com.cybershield.repo.AnalysisRepository; import com.cybershield.service.*; import org.springframework.web.bind.annotation.*; import java.util.*;
@RestController @RequestMapping("/api") public class AnalysisController {private final AuthService auth;private final AnalysisService service;private final AnalysisRepository repo;public AnalysisController(AuthService a,AnalysisService s,AnalysisRepository r){auth=a;service=s;repo=r;}
 record Request(String type,String input){}
 @PostMapping("/analyze") public Analysis analyze(@RequestHeader("X-Auth-Token") String t,@RequestBody Request r){return service.analyze(auth.user(t).getId(),r.type(),r.input());}
 @GetMapping("/history") public List<Analysis> history(@RequestHeader("X-Auth-Token") String t){return repo.findTop20ByUserIdOrderByCreatedAtDesc(auth.user(t).getId());}
 @GetMapping("/stats") public Map<String,Object> stats(@RequestHeader("X-Auth-Token") String t){Long id=auth.user(t).getId();List<Analysis> h=repo.findTop20ByUserIdOrderByCreatedAtDesc(id);long high=h.stream().filter(x->"HIGH".equals(x.getRisk())).count();return Map.of("total",repo.countByUserId(id),"high",high,"recent",h.size());}
}
