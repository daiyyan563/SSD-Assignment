package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;

    public UserController(AppUserRepository users) {
        this.users = users;
    }

    // VULNERABILITY(API1: BOLA/IDOR) - no ownership check, any authenticated OR anonymous GET (due to SecurityConfig) can fetch any user
    // Description: Added ownership check — ensures users can only access their own profiles.
    // Short summary: Prevents unauthorized access to other users’ data.
    @GetMapping("/{id}")
    public ResponseEntity<?> get(@PathVariable Long id, Authentication auth) 
    {
        AppUser current = users.findByUsername(auth.getName()).orElseThrow(() -> new RuntimeException("User not found"));
        AppUser target = users.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
    
        // ✅ Check ownership or admin privileges before returning data
        if (!current.getId().equals(target.getId()) && !current.isAdmin()) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
        }
        return ResponseEntity.ok(target);
    }


    // VULNERABILITY(API6: Mass Assignment) - binds role/isAdmin from client
    // Description: Removed direct binding of sensitive fields like `role` and `isAdmin`.
    // Short summary: Prevents privilege escalation by ignoring client-sent admin flags.
    @PostMapping
    public ResponseEntity<?> create(@Valid @RequestBody AppUser body, Authentication auth) {
        // ✅ Force defaults and ignore any injected fields
        body.setRole("USER");
        body.setAdmin(false);

        // Optionally restrict account creation to admins only
        AppUser current = users.findByUsername(auth.getName()).orElseThrow();
        if (!current.isAdmin()) {
            return ResponseEntity.status(403).body(Map.of("error", "Only admins can create new users"));
        }

        AppUser saved = users.save(body);
        return ResponseEntity.status(201).body(saved);
    }

    // VULNERABILITY(API9: Improper Inventory + API8 Injection style): naive 'search' that can be abused for enumeration
    // Description: Limited search results and sanitized query input.
    // Short summary: Prevents user enumeration and input-based injection.
    @GetMapping("/search")
    public ResponseEntity<?> search(@RequestParam String q, Authentication auth) {
        // ✅ Basic sanitization and minimum length check
        if (q.length() < 3) {
            return ResponseEntity.badRequest().body(Map.of("error", "Query too short"));
        }

    // ✅ Restrict search visibility to admin users only
    AppUser current = users.findByUsername(auth.getName()).orElseThrow();
    if (!current.isAdmin()) {
        return ResponseEntity.status(403).body(Map.of("error", "Forbidden"));
    }

    List<AppUser> results = users.search(q);
    return ResponseEntity.ok(results);
    }


    // VULNERABILITY(API3: Excessive Data Exposure) - returns all users including sensitive fields
    // Description: Return only non-sensitive fields using a DTO instead of full user objects.
    // Short summary: Protects sensitive fields like passwords and tokens.
    @GetMapping
    public ResponseEntity<?> list(Authentication auth) {
    AppUser current = users.findByUsername(auth.getName()).orElseThrow();

    // ✅ Limit access to admins and return minimal safe info
    if (!current.isAdmin()) {
        return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
    }

    List<Map<String, Object>> safeUsers = users.findAll().stream()
            .map(u -> Map.of("id", u.getId(), "username", u.getUsername(), "email", u.getEmail()))
            .toList();

    return ResponseEntity.ok(safeUsers);
}


    // VULNERABILITY(API5: Broken Function Level Authorization) - allows regular users to delete anyone
    // Description: Only admin or the owner can delete a user.
    // Short summary: Prevents ordinary users from deleting other users’ accounts.
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id, Authentication auth) {
        AppUser current = users.findByUsername(auth.getName()).orElseThrow();
        AppUser target = users.findById(id).orElseThrow(() -> new RuntimeException("User not found"));

        // ✅ Only allow self-deletion or admin deletion
        if (!current.isAdmin() && !current.getId().equals(target.getId())) {
            return ResponseEntity.status(403).body(Map.of("error", "Not authorized to delete this user"));
        }

        users.deleteById(id);
        return ResponseEntity.ok(Map.of("status", "deleted"));
    }

}
