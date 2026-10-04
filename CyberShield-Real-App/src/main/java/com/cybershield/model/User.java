package com.cybershield.model;
import jakarta.persistence.*; import java.time.LocalDateTime;
@Entity @Table(name="users") public class User {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) private Long id;
 @Column(nullable=false) private String name; @Column(nullable=false,unique=true) private String email; @Column(nullable=false) private String passwordHash;
 private String phone; private String avatar; private boolean alertsEnabled=true; private LocalDateTime createdAt=LocalDateTime.now(); private LocalDateTime updatedAt=LocalDateTime.now();
 public Long getId(){return id;} public String getName(){return name;} public void setName(String v){name=v;} public String getEmail(){return email;} public void setEmail(String v){email=v;} public String getPasswordHash(){return passwordHash;} public void setPasswordHash(String v){passwordHash=v;} public String getPhone(){return phone;} public void setPhone(String v){phone=v;} public String getAvatar(){return avatar;} public void setAvatar(String v){avatar=v;} public boolean isAlertsEnabled(){return alertsEnabled;} public void setAlertsEnabled(boolean v){alertsEnabled=v;} public LocalDateTime getCreatedAt(){return createdAt;} public LocalDateTime getUpdatedAt(){return updatedAt;} public void touch(){updatedAt=LocalDateTime.now();}
}
