package com.authprovider.controller;

import com.authprovider.entity.OtpToken;
import com.authprovider.entity.Person;
import com.authprovider.service.OtpProvisioningSupport;
import com.authprovider.service.PersonService;
import com.authprovider.service.QrCodeGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/v1/api/persons")
@RequiredArgsConstructor
public class PersonController {

    private final PersonService personService;
    private final QrCodeGenerator qrCodeGenerator;

    public record CreateTokenRequest(String label, String secret) {
    }

    public record TokenProvisionResponse(Long id, Long personId, String label, boolean enabled,
                                         String secret, String otpAuthUri, String qrCode) {
    }

    @GetMapping("/all")
    public List<Person> getAllPersons() {
        return personService.getAllPersons();
    }

    @GetMapping("/{id}")
    public Person getPersonById(@PathVariable Long id) {
        return personService.getPersonOrThrow(id);
    }

    @PostMapping("/create")
    public Person createPerson(@RequestBody Person person) {
        return personService.createPerson(person);
    }

    @PutMapping("/{id}")
    public Person updatePerson(@PathVariable Long id, @RequestBody Person person) {
        return personService.updatePerson(id, person);
    }

    @GetMapping("/{id}/tokens")
    public List<OtpToken> getTokens(@PathVariable Long id) {
        return personService.getTokensForPerson(id);
    }

    @PostMapping("/{id}/tokens")
    public TokenProvisionResponse createToken(@PathVariable Long id,
                                              @RequestBody(required = false) CreateTokenRequest req) {
        String label = req == null ? null : req.label();
        String secret = req == null ? null : req.secret();
        OtpToken token = personService.createToken(id, label, secret);
        return toProvisionResponse(token);
    }

    @PostMapping("/tokens/{tokenId}/rotate")
    public TokenProvisionResponse rotateToken(@PathVariable Long tokenId) {
        return toProvisionResponse(personService.rotateTokenSecret(tokenId));
    }

    private TokenProvisionResponse toProvisionResponse(OtpToken token) {
        String label = token.getPerson() != null ? token.getPerson().getDisplayName() : token.getLabel();
        String otpAuthUri = OtpProvisioningSupport.buildOtpAuthUri(qrCodeGenerator, label, token.getSecret());
        String qrCode = null;
        try {
            qrCode = OtpProvisioningSupport.generateQrImage(qrCodeGenerator, otpAuthUri);
        } catch (Exception e) {
            log.warn("Failed to generate provisioning QR code for token id {}", token.getId(), e);
        }
        return new TokenProvisionResponse(token.getId(), token.getPersonId(), token.getLabel(),
                token.isEnabled(), token.getSecret(), otpAuthUri, qrCode);
    }
}
