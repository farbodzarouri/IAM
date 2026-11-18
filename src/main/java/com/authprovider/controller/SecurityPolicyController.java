package com.authprovider.controller;

import com.authprovider.dto.SecurityPolicyRequest;
import com.authprovider.entity.SecurityPolicy;
import com.authprovider.service.SecurityPolicyService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/api/policies")
@RequiredArgsConstructor
public class SecurityPolicyController {

    private final SecurityPolicyService policyService;

    @GetMapping("/current")
    public SecurityPolicy getCurrentPolicy() {
        return policyService.current();
    }

    @PutMapping("/current")
    public SecurityPolicy updateCurrentPolicy(@RequestBody(required = false) SecurityPolicyRequest request) {
        return policyService.updateCurrentPolicy(request);
    }
}
