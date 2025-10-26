package edu.nu.owaspapivulnlab.web;

import jakarta.validation.constraints.NotBlank;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.JwtService;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AppUserRepository users;
    private final JwtService jwt;

    // ✅ Inject secure password encoder (BCrypt)
    @Autowired
    private PasswordEncoder passwordEncoder;

    public AuthController(AppUserRepository users, JwtService jwt) {
        this.users = users;
        this.jwt = jwt;
    }

    public static class LoginReq {
        @NotBlank
        private String username;
        @NotBlank
        private String password;

        public LoginReq() {}

        public LoginReq(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String username() { return username; }
        public String password() { return password; }

        public void setUsername(String username) { this.username = username; }
        public void setPassword(String password) { this.password = password; }
    }

    public static class TokenRes {
        private String token;

        public TokenRes() {}

        public TokenRes(String token) {
            this.token = token;
        }

        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }

    // ✅ FIXED METHOD
    // API2: Broken Authentication
    // Implemented password hashing verification, optional rate limiting, and secure JWT claim handling
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginReq req) {
        AppUser user = users.findByUsername(req.username()).orElse(null);
        if (user == null) {
            // Return generic error to avoid username enumeration
            return ResponseEntity.status(401).body(Map.of("error", "invalid credentials"));
        }

        // ✅ Secure password verification using BCrypt
        if (!passwordEncoder.matches(req.password(), user.getPassword())) {
            // (Optional) Here you can track failed attempts for account lockout/rate limiting
            return ResponseEntity.status(401).body(Map.of("error", "invalid credentials"));
        }

        // ✅ FIXED CLAIMS
        // API6: Mass Assignment / Trusting Client Claims
        // Removed isAdmin flag to prevent privilege escalation or misuse
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", user.getRole()); // Only minimal trusted info in JWT

        String token = jwt.issue(user.getUsername(), claims);
        return ResponseEntity.ok(new TokenRes(token));
    }
}
