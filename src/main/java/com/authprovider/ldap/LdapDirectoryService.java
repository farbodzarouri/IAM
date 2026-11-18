package com.authprovider.ldap;

import com.authprovider.config.LdapProperties;
import com.authprovider.entity.LdapDirectory;
import com.authprovider.exception.BadRequestException;
import com.authprovider.exception.ConflictException;
import com.authprovider.exception.ResourceNotFoundException;
import com.authprovider.repository.LdapDirectoryRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
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
        return repository.findByEnabledTrueOrderByPriorityAscIdAsc().stream()
                .filter(LdapDirectory::isUserEnabled)
                .toList();
    }

    public List<LdapDirectory> enabledAdminDirectories() {
        return repository.findByEnabledTrueOrderByPriorityAscIdAsc().stream()
                .filter(LdapDirectory::isAdminEnabled)
                .toList();
    }

    public Optional<LdapDirectory> findByName(String name) {
        return name == null ? Optional.empty() : repository.findByName(name);
    }

    public List<LdapDirectory> getAllDirectories() {
        return repository.findAllByOrderByPriorityAscIdAsc();
    }

    public LdapDirectory getDirectoryOrThrow(Long id) {
        if (id == null) {
            throw new ResourceNotFoundException("LDAP directory not found: null");
        }
        return repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("LDAP directory not found: " + id));
    }

    public LdapDirectory createDirectory(LdapDirectory directory) {
        if (directory == null) {
            throw new BadRequestException("LDAP directory payload is required");
        }
        directory.setId(null);
        String name = normalizeDirectoryName(directory.getName());
        directory.setName(name);
        if (directory.getUrl() == null) {
            directory.setUrl("");
        } else {
            directory.setUrl(directory.getUrl().trim());
        }
        if (repository.findByName(name).isPresent()) {
            throw new ConflictException("LDAP directory already exists: " + name);
        }
        validateDirectoryIfEnabled(directory);
        return repository.saveAndFlush(directory);
    }

    public LdapDirectory updateDirectory(Long id, LdapDirectory updated) {
        LdapDirectory existing = getDirectoryOrThrow(id);
        if (updated == null) {
            throw new BadRequestException("LDAP directory payload is required");
        }
        String name = normalizeDirectoryName(updated.getName());
        repository.findByName(name).ifPresent(other -> {
            if (!Objects.equals(other.getId(), id)) {
                throw new ConflictException("LDAP directory already exists: " + name);
            }
        });
        existing.setName(name);
        existing.setRealm(updated.getRealm());
        existing.setEnabled(updated.isEnabled());
        existing.setUserEnabled(updated.isUserEnabled());
        existing.setAdminEnabled(updated.isAdminEnabled());
        existing.setPriority(updated.getPriority());
        existing.setUrl(updated.getUrl() == null ? "" : updated.getUrl().trim());
        existing.setBaseDn(updated.getBaseDn());
        existing.setUserSearchFilter(updated.getUserSearchFilter());
        existing.setUserDnPattern(updated.getUserDnPattern());
        existing.setBindDn(updated.getBindDn());
        if (updated.getBindPassword() != null && !updated.getBindPassword().isBlank()) {
            existing.setBindPassword(updated.getBindPassword());
        }
        existing.setAutoProvision(updated.isAutoProvision());
        existing.setFallbackToLocal(updated.isFallbackToLocal());
        existing.setConnectTimeoutMs(updated.getConnectTimeoutMs());
        existing.setReadTimeoutMs(updated.getReadTimeoutMs());
        existing.setReferral(updated.getReferral());
        existing.setUsernameAttributes(updated.getUsernameAttributes());
        validateDirectoryIfEnabled(existing);
        return repository.saveAndFlush(existing);
    }

    public void deleteDirectory(Long id) {
        LdapDirectory existing = getDirectoryOrThrow(id);
        repository.delete(existing);
    }

    public static void validateDirectoryIfEnabled(LdapDirectory directory) {
        if (!directory.isEnabled()) {
            return;
        }
        try {
            new JndiLdapDirectoryAuthenticator(toProperties(directory)).validateConfiguration();
        } catch (IllegalStateException e) {
            throw new BadRequestException(e.getMessage());
        }
    }

    private static String normalizeDirectoryName(String raw) {
        String name = raw == null ? "" : raw.trim();
        if (name.isEmpty()) {
            throw new BadRequestException("LDAP directory name is required");
        }
        return name;
    }

    @Override
    public boolean isEnabled() {
        return !enabledDirectories().isEmpty();
    }

    @Override
    public boolean isAdminEnabled() {
        return !enabledAdminDirectories().isEmpty();
    }

    @Override
    public boolean isFallbackToLocal(String username) {
        return isFallbackToLocal(route(username, username));
    }

    @Override
    public boolean isAdminFallbackToLocal(String username) {
        return isFallbackToLocal(routeAdmin(username, username));
    }

    @Override
    public boolean isAutoProvision(DirectoryAuthenticationResult result) {
        return isAutoProvision(enabledDirectories(), result);
    }

    @Override
    public boolean isAdminAutoProvision(DirectoryAuthenticationResult result) {
        return isAutoProvision(enabledAdminDirectories(), result);
    }

    /**
     * Routes {@code qualifiedName}. If its realm matches enabled user directories they are returned
     * with the realm stripped from the login name; otherwise all enabled user directories are returned
     * together with {@code unqualifiedName}.
     */
    public Route route(String qualifiedName, String unqualifiedName) {
        return route(enabledDirectories(), qualifiedName, unqualifiedName);
    }

    /** Routes {@code qualifiedName} across directories enabled for {@code Admin} authentication. */
    public Route routeAdmin(String qualifiedName, String unqualifiedName) {
        return route(enabledAdminDirectories(), qualifiedName, unqualifiedName);
    }

    private static boolean isFallbackToLocal(Route route) {
        return !route.directories().isEmpty()
                && route.directories().stream().allMatch(LdapDirectory::isFallbackToLocal);
    }

    private boolean isAutoProvision(List<LdapDirectory> enabled, DirectoryAuthenticationResult result) {
        if (result != null && result.directory() != null) {
            Optional<LdapDirectory> directory = findByName(result.directory());
            if (directory.isPresent()) {
                return directory.get().isAutoProvision();
            }
        }
        return !enabled.isEmpty() && enabled.get(0).isAutoProvision();
    }

    private static Route route(List<LdapDirectory> enabled, String qualifiedName, String unqualifiedName) {
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
