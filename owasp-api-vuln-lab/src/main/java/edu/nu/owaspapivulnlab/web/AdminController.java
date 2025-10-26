package edu.nu.owaspapivulnlab.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    // VULNERABILITY(API7: Security Misconfiguration) - may be exposed via incorrect matcher order
    // Restricted /metrics endpoint to ADMIN role and sanitized sensitive output
    @GetMapping("/metrics")
    @PreAuthorize("hasRole('ADMIN')") // ✅ Restrict access to admins only
    public Map<String, Object> metrics() 
    {
        RuntimeMXBean rt = ManagementFactory.getRuntimeMXBean();
        Map<String, Object> metricsMap = new HashMap<>();

        // ✅ Limit information exposed (omit java version & thread details)
        metricsMap.put("uptimeMs", rt.getUptime());
        metricsMap.put("appStatus", "running");

        return metricsMap;
    }

}
