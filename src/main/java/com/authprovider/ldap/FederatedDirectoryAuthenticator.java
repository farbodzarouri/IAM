package com.authprovider.ldap;

import com.authprovider.config.LdapProperties;
import com.authprovider.entity.LdapDirectory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.naming.directory.InitialDirContext;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * {@link DirectoryAuthenticator} federating all persisted {@link LdapDirectory} entries.
 * <ul>
 *     <li>Qualified names ({@code REALM\\user}, {@code user@realm}) whose realm matches a directory are
 *     sent only to that directory (realm stripped).</li>
 *     <li>Other names are evaluated against the enabled directories in priority order. Evaluation stops
 *     at the first directory that knows the user (successful bind or wrong password) so that at most one
 *     user bind is performed, and fails closed if a directory is unavailable.</li>
 * </ul>
 */
@Slf4j
@Component
public class FederatedDirectoryAuthenticator implements DirectoryAuthenticator {

    private final LdapDirectoryService directoryService;
    private final LdapContextFactory contextFactory;
    private final Map<Long, CachedAuthenticator> authenticators = new ConcurrentHashMap<>();

    private record CachedAuthenticator(LdapProperties settings, JndiLdapDirectoryAuthenticator authenticator,
                                       RuntimeException configurationError) {
    }

    @Autowired
    public FederatedDirectoryAuthenticator(LdapDirectoryService directoryService) {
        this(directoryService, InitialDirContext::new);
    }

    public FederatedDirectoryAuthenticator(LdapDirectoryService directoryService, LdapContextFactory contextFactory) {
        this.directoryService = directoryService;
        this.contextFactory = contextFactory;
    }

    @Override
    public boolean isRealmAware() {
        return true;
    }

    @Override
    public DirectoryAuthenticationResult authenticate(String username, String password) {
        return authenticateQualified(username, username, password);
    }

    @Override
    public DirectoryAuthenticationResult authenticateQualified(String qualifiedName, String unqualifiedName, String password) {
        if (qualifiedName == null || qualifiedName.isBlank() || password == null || password.isEmpty()) {
            return DirectoryAuthenticationResult.invalidCredentials();
        }
        LdapDirectoryService.Route route = directoryService.route(qualifiedName, unqualifiedName);
        List<LdapDirectory> directories = route.directories();
        if (directories.isEmpty()) {
            return DirectoryAuthenticationResult.userNotFound();
        }
        if (route.loginName() == null || route.loginName().isBlank()) {
            return DirectoryAuthenticationResult.invalidCredentials();
        }
        DirectoryAuthenticationResult last = DirectoryAuthenticationResult.userNotFound();
        for (LdapDirectory directory : directories) {
            DirectoryAuthenticationResult result = authenticate(directory, route.loginName(), password)
                    .withDirectory(directory.getName());
            switch (result.status()) {
                case AUTHENTICATED:
                case INVALID_CREDENTIALS:
                case UNAVAILABLE:
                    return result;
                case USER_NOT_FOUND:
                default:
                    last = result;
            }
        }
        return last;
    }

    private DirectoryAuthenticationResult authenticate(LdapDirectory directory, String loginName, String password) {
        CachedAuthenticator cached = authenticatorFor(directory);
        if (cached.configurationError() != null) {
            log.error("Directory '{}' is misconfigured: {}", directory.getName(), cached.configurationError().getMessage());
            return DirectoryAuthenticationResult.unavailable();
        }
        try {
            DirectoryAuthenticationResult result = cached.authenticator().authenticate(loginName, password);
            return result == null ? DirectoryAuthenticationResult.unavailable() : result;
        } catch (RuntimeException e) {
            log.error("Directory '{}' authentication failed unexpectedly", directory.getName(), e);
            return DirectoryAuthenticationResult.unavailable();
        }
    }

    private CachedAuthenticator authenticatorFor(LdapDirectory directory) {
        LdapProperties settings = LdapDirectoryService.toProperties(directory);
        Long key = directory.getId() == null ? Long.valueOf(System.identityHashCode(directory)) : directory.getId();
        CachedAuthenticator cached = authenticators.get(key);
        if (cached != null && cached.settings().equals(settings)) {
            return cached;
        }
        JndiLdapDirectoryAuthenticator authenticator = new JndiLdapDirectoryAuthenticator(settings, contextFactory);
        RuntimeException error = null;
        try {
            authenticator.validateConfiguration();
        } catch (RuntimeException e) {
            error = e;
        }
        CachedAuthenticator created = new CachedAuthenticator(settings, authenticator, error);
        if (directory.getId() != null) {
            authenticators.put(key, created);
        }
        return created;
    }
}
