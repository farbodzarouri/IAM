package com.authprovider.ldap;

import com.authprovider.config.LdapProperties;
import com.authprovider.entity.LdapDirectory;
import com.authprovider.repository.LdapDirectoryRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Access to the federated {@link LdapDirectory} configuration and realm routing.
 * <p>
 * A user name is <em>qualified</em> when it has the form {@code REALM\\user} or {@code user@realm}.
 * Qualified names whose realm matches the realm identifier (or one of the comma separated aliases) of
 * enabled directories are routed only to those directories; all other names are evaluated against all
 * enabled directories in ascending priority order.
 */
@Slf4j
@Service
public class LdapDirectoryService implements DirectoryConfiguration {

    private final LdapDirectoryRepository repository;

    public LdapDirectoryService(LdapDirectoryRepository repository) {
        this.repository = repository;
    }

    /**
     * Routing decision for a user name.
     *
     * @param directories directories to evaluate, in priority order
     * @param loginName   user name to present to the directories
     * @param realmMatched true if a qualified name was routed by realm
     */
    public record Route(List<LdapDirectory> directories, String loginName, boolean realmMatched) {
    }

    /** Parsed user name. {@code realm} is {@code null} for unqualified names. */
    public record QualifiedName(String realm, String user) {
        public boolean isQualified() {
            return realm != null;
        }
    }

    public List<LdapDirectory> enabledDirectories() {
        return repository.findByEnabledTrueOrderByPriorityAscIdAsc();
    }

    public Optional<LdapDirectory> findByName(String name) {
        return name == null ? Optional.empty() : repository.findByName(name);
    }

    @Override
    public boolean isEnabled() {
        return !enabledDirectories().isEmpty();
    }

    @Override
    public boolean isFallbackToLocal(String username) {
        Route route = route(username, username);
        return !route.directories().isEmpty()
                && route.directories().stream().allMatch(LdapDirectory::isFallbackToLocal);
    }

    @Override
    public boolean isAutoProvision(DirectoryAuthenticationResult result) {
        if (result != null && result.directory() != null) {
            Optional<LdapDirectory> directory = findByName(result.directory());
            if (directory.isPresent()) {
                return directory.get().isAutoProvision();
            }
        }
        List<LdapDirectory> enabled = enabledDirectories();
        return !enabled.isEmpty() && enabled.get(0).isAutoProvision();
    }

    /**
     * Routes {@code qualifiedName}. If its realm matches enabled directories they are returned with the
     * realm stripped from the login name; otherwise all enabled directories are returned together with
     * {@code unqualifiedName}.
     */
    public Route route(String qualifiedName, String unqualifiedName) {
        List<LdapDirectory> enabled = enabledDirectories();
        QualifiedName parsed = parse(qualifiedName);
        if (parsed.isQualified()) {
            List<LdapDirectory> matching = new ArrayList<>();
            for (LdapDirectory directory : enabled) {
                if (realmMatches(directory, parsed.realm())) {
                    matching.add(directory);
                }
            }
            if (!matching.isEmpty()) {
                return new Route(List.copyOf(matching), parsed.user(), true);
            }
        }
        String loginName = unqualifiedName == null ? qualifiedName : unqualifiedName;
        return new Route(List.copyOf(enabled), loginName == null ? null : loginName.trim(), false);
    }

    /** Splits {@code REALM\\user} and {@code user@realm}; other values are unqualified. */
    public static QualifiedName parse(String userName) {
        if (userName == null) {
            return new QualifiedName(null, null);
        }
        String trimmed = userName.trim();
        int backslash = trimmed.indexOf('\\');
        if (backslash > 0 && backslash < trimmed.length() - 1) {
            String realm = trimmed.substring(0, backslash).trim();
            String user = trimmed.substring(backslash + 1).trim();
            if (!realm.isEmpty() && !user.isEmpty()) {
                return new QualifiedName(realm, user);
            }
        }
        int at = trimmed.lastIndexOf('@');
        if (at > 0 && at < trimmed.length() - 1) {
            String user = trimmed.substring(0, at).trim();
            String realm = trimmed.substring(at + 1).trim();
            if (!realm.isEmpty() && !user.isEmpty()) {
                return new QualifiedName(realm, user);
            }
        }
        return new QualifiedName(null, trimmed);
    }

    static boolean realmMatches(LdapDirectory directory, String realm) {
        if (directory.getRealm() == null || directory.getRealm().isBlank() || realm == null) {
            return false;
        }
        String wanted = realm.trim().toLowerCase(Locale.ROOT);
        return Arrays.stream(directory.getRealm().split(","))
                .map(alias -> alias.trim().toLowerCase(Locale.ROOT))
                .anyMatch(alias -> !alias.isEmpty() && alias.equals(wanted));
    }

    /** Converts a persisted directory into the connection settings used by {@link JndiLdapDirectoryAuthenticator}. */
    public static LdapProperties toProperties(LdapDirectory directory) {
        LdapProperties properties = new LdapProperties();
        properties.setEnabled(true);
        properties.setUrl(directory.getUrl());
        properties.setBaseDn(directory.getBaseDn());
        properties.setUserSearchFilter(directory.getUserSearchFilter());
        properties.setUserDnPattern(directory.getUserDnPattern());
        properties.setBindDn(directory.getBindDn());
        properties.setBindPassword(directory.getBindPassword());
        properties.setAutoProvision(directory.isAutoProvision());
        properties.setFallbackToLocal(directory.isFallbackToLocal());
        properties.setConnectTimeoutMs(directory.getConnectTimeoutMs());
        properties.setReadTimeoutMs(directory.getReadTimeoutMs());
        properties.setReferral(directory.getReferral());
        List<String> attributes = new ArrayList<>();
        if (directory.getUsernameAttributes() != null) {
            for (String attribute : directory.getUsernameAttributes().split(",")) {
                if (!attribute.isBlank()) {
                    attributes.add(attribute.trim());
                }
            }
        }
        properties.setUsernameAttributes(attributes);
        return properties;
    }

    /** Builds a directory record from the legacy {@code ldap.*} properties. */
    public static LdapDirectory fromProperties(String name, LdapProperties properties) {
        List<String> attributes = properties.getUsernameAttributes() == null ? List.of() : properties.getUsernameAttributes();
        return LdapDirectory.builder()
                .name(name)
                .realm(blankToNull(properties.getRealm()))
                .enabled(properties.isEnabled())
                .priority(properties.getPriority())
                .url(properties.getUrl() == null ? "" : properties.getUrl().trim())
                .baseDn(properties.getBaseDn())
                .userSearchFilter(properties.getUserSearchFilter())
                .userDnPattern(blankToNull(properties.getUserDnPattern()))
                .bindDn(blankToNull(properties.getBindDn()))
                .bindPassword(blankToNull(properties.getBindPassword()))
                .autoProvision(properties.isAutoProvision())
                .fallbackToLocal(properties.isFallbackToLocal())
                .connectTimeoutMs(properties.getConnectTimeoutMs())
                .readTimeoutMs(properties.getReadTimeoutMs())
                .referral(properties.getReferral())
                .usernameAttributes(String.join(",", attributes.stream().filter(a -> a != null && !a.isBlank())
                        .map(String::trim).toList()))
                .build();
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
