package com.authprovider.config;

import lombok.Data;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@Data
@ConfigurationProperties(prefix = "ldap")
public class LdapProperties {

    private boolean enabled = false;
    private String url = "ldap://localhost:389";
    private String baseDn = "dc=example,dc=org";
    private String userSearchFilter = "(&(objectClass=person)(|(uid={0})(sAMAccountName={0})))";
    private String userDnPattern;
    private String bindDn;
    @ToString.Exclude
    private String bindPassword;
    private boolean autoProvision = true;
    private boolean fallbackToLocal = false;
    private int connectTimeoutMs = 5000;
    private int readTimeoutMs = 10000;
    private String referral = "ignore";
    private List<String> usernameAttributes = new ArrayList<>(List.of("uid", "sAMAccountName"));
}
