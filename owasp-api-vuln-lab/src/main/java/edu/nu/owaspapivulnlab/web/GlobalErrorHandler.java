package edu.nu.owaspapivulnlab.web;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;

// VULNERABILITY(API7): overly verbose error responses exposing stack traces, DB info, or class names
@ControllerAdvice
public class GlobalErrorHandler {

    // ✅ FIX for API7: Return only generic error message without exposing internal exception details
    // Short description: Prevents information leakage that aids attackers in reconnaissance.
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> all(Exception e) {
        Map<String, String> errorMap = new HashMap<>();
        // ✅ Only return a generic message to the client
        errorMap.put("error", "An unexpected error occurred. Please contact support if the issue persists.");
        // Optionally log details internally for debugging
        System.err.println("[ERROR] " + e.getClass().getName() + ": " + e.getMessage());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorMap);
    }

    // ✅ FIX for API7 (DB-specific case): Hide database errors from clients
    // Short description: Prevents attackers from learning database schema or query errors.
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<?> db(DataAccessException e) {
        Map<String, String> errorMap = new HashMap<>();
        // ✅ Replace detailed DB error message with a user-friendly generic one
        errorMap.put("error", "A database error occurred. Please try again later.");
        // Log actual DB exception internally for developers
        System.err.println("[DB ERROR] " + e.getMessage());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMap);
    }
}
