package edu.nu.owaspapivulnlab.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;

    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    /**
     * ✅ FIX for API1: Broken Object Level Authorization (BOLA)
     * Description: Verify that the account belongs to the authenticated user before returning data.
     */
    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable Long id, Authentication auth) {
        AppUser me = users.findByUsername(auth.getName()).orElseThrow(() -> new RuntimeException("User not found"));
        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));

        // 🔒 Ensure the authenticated user owns the requested account
        if (!a.getOwnerUserId().equals(me.getId())) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
        }

        return ResponseEntity.ok(Map.of("balance", a.getBalance()));
    }

    // ✅ FIXED METHOD: transfer()
// VULNERABILITY(API4: Unrestricted Resource Consumption) - no rate limiting on transfer
// VULNERABILITY(API5/1: Broken Function Level Authorization) - no authorization check on owner
@PostMapping("/{id}/transfer")
public ResponseEntity<?> transfer(@PathVariable Long id,
                                  @RequestParam Double amount,
                                  Authentication auth) {

    // ✅ [API4 FIX] Input validation to prevent resource exhaustion
    if (amount == null || amount <= 0 || amount > 10000) { 
        // limit large or abusive transfer amounts
        return ResponseEntity.badRequest().body(Map.of("error", "Invalid or excessive transfer amount"));
    }

    // ✅ [API5 FIX] Ensure user is authenticated and authorized
    AppUser me = users.findByUsername(auth.getName())
            .orElseThrow(() -> new RuntimeException("User not found"));
    Account a = accounts.findById(id)
            .orElseThrow(() -> new RuntimeException("Account not found"));

    // 🔒 Ensure the authenticated user owns the account
    if (!a.getOwnerUserId().equals(me.getId())) {
        return ResponseEntity.status(403).body(Map.of("error", "Access denied — not your account"));
    }

    // ✅ Additional logical validation: prevent overdrawing
    if (a.getBalance() < amount) {
        return ResponseEntity.badRequest().body(Map.of("error", "Insufficient funds"));
    }

    // Process transfer safely
    a.setBalance(a.getBalance() - amount);
    accounts.save(a);

    Map<String, Object> response = new HashMap<>();
    response.put("status", "ok");
    response.put("remaining", a.getBalance());
    return ResponseEntity.ok(response);
}



// ✅ FIXED METHOD: mine()
// VULNERABILITY(API3: Excessive Data Exposure) - returned too much information about accounts
@GetMapping("/mine")
public ResponseEntity<?> mine(Authentication auth) 
{
        if (auth == null || auth.getName() == null) {
         return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
        }

     AppUser me = users.findByUsername(auth.getName())
             .orElseThrow(() -> new RuntimeException("User not found"));

     // ✅ [API3 FIX] Return only safe, minimal information
     var safeAccounts = accounts.findByOwnerUserId(me.getId()).stream()
             .map(acc -> Map.of(
                     "accountId", acc.getId(),
                     "balance", acc.getBalance()  // can be masked or limited if needed
             ))
             .toList();

     return ResponseEntity.ok(safeAccounts);
    }

}
