package com.cybershield.service;
import com.cybershield.model.User; import com.cybershield.repo.UserRepository; import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder; import org.springframework.stereotype.Service; import java.util.*; import java.util.concurrent.ConcurrentHashMap;
@Service public class AuthService {
 private final UserRepository users; private final BCryptPasswordEncoder encoder=new BCryptPasswordEncoder(); private final Map<String,Long> sessions=new ConcurrentHashMap<>();
 public AuthService(UserRepository u){users=u;}
 public User signup(String name,String email,String password){ if(users.findByEmail(email).isPresent()) throw new IllegalArgumentException("Email already registered"); User u=new User();u.setName(name.trim());u.setEmail(email.trim().toLowerCase());u.setPasswordHash(encoder.encode(password));return users.save(u); }
 public Map<String,Object> login(String email,String password){ User u=users.findByEmail(email.trim().toLowerCase()).orElseThrow(()->new IllegalArgumentException("Invalid email or password")); if(!encoder.matches(password,u.getPasswordHash())) throw new IllegalArgumentException("Invalid email or password"); String token=UUID.randomUUID().toString();sessions.put(token,u.getId());return Map.of("token",token,"user",u); }
 public User user(String token){Long id=sessions.get(token);if(id==null)throw new IllegalArgumentException("Session expired");return users.findById(id).orElseThrow();}
 public void logout(String token){sessions.remove(token);}
}
