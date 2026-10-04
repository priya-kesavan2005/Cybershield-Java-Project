package com.cybershield.model;
import jakarta.persistence.*; import java.time.LocalDateTime;
@Entity @Table(name="analyses") public class Analysis {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) private Long id; private Long userId; private String type; @Column(columnDefinition="TEXT") private String inputText; private String risk; private int score; @Column(columnDefinition="TEXT") private String reasons; private LocalDateTime createdAt=LocalDateTime.now();
 public Long getId(){return id;} public Long getUserId(){return userId;} public void setUserId(Long v){userId=v;} public String getType(){return type;} public void setType(String v){type=v;} public String getInputText(){return inputText;} public void setInputText(String v){inputText=v;} public String getRisk(){return risk;} public void setRisk(String v){risk=v;} public int getScore(){return score;} public void setScore(int v){score=v;} public String getReasons(){return reasons;} public void setReasons(String v){reasons=v;} public LocalDateTime getCreatedAt(){return createdAt;}
}
