package com.authprovider.service;

import com.authprovider.dto.ClientAssignmentRequest;
import com.authprovider.dto.ClientSummaryResponse;
import com.authprovider.entity.ClientType;
import com.authprovider.entity.OAuthClient;
import com.authprovider.entity.RadiusClient;
import com.authprovider.entity.User;
import com.authprovider.entity.UserOAuthClient;
import com.authprovider.entity.UserRadiusClient;
import com.authprovider.exception.BadRequestException;
import com.authprovider.exception.ConflictException;
import com.authprovider.exception.ResourceNotFoundException;
import com.authprovider.repository.OAuthClientRepository;
import com.authprovider.repository.RadiusClientRepository;
import com.authprovider.repository.UserOAuthClientRepository;
import com.authprovider.repository.UserRadiusClientRepository;
import com.authprovider.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

@Slf4j
@Service
public class UserClientAssignmentServiceImpl implements UserClientAssignmentService {

    private final UserRepository userRepository;
    private final RadiusClientRepository radiusClientRepository;
    private final OAuthClientRepository oauthClientRepository;
    private final UserRadiusClientRepository radiusAssignmentRepository;
    private final UserOAuthClientRepository oauthAssignmentRepository;
    private final TransactionTemplate transactionTemplate;

    public UserClientAssignmentServiceImpl(UserRepository userRepository,
                                           RadiusClientRepository radiusClientRepository,
                                           OAuthClientRepository oauthClientRepository,
                                           UserRadiusClientRepository radiusAssignmentRepository,
                                           UserOAuthClientRepository oauthAssignmentRepository) {
        this(userRepository, radiusClientRepository, oauthClientRepository,
                radiusAssignmentRepository, oauthAssignmentRepository, null);
    }

    @Autowired
    public UserClientAssignmentServiceImpl(UserRepository userRepository,
                                           RadiusClientRepository radiusClientRepository,
                                           OAuthClientRepository oauthClientRepository,
                                           UserRadiusClientRepository radiusAssignmentRepository,
                                           UserOAuthClientRepository oauthAssignmentRepository,
                                           PlatformTransactionManager transactionManager) {
        this.userRepository = userRepository;
        this.radiusClientRepository = radiusClientRepository;
        this.oauthClientRepository = oauthClientRepository;
        this.radiusAssignmentRepository = radiusAssignmentRepository;
        this.oauthAssignmentRepository = oauthAssignmentRepository;
        this.transactionTemplate = transactionManager == null ? null : new TransactionTemplate(transactionManager);
    }

    // ---- RADIUS ------------------------------------------------------------------------------------

    @Override
    @Transactional(readOnly = true)
    public List<UserRadiusClient> getRadiusAssignments(Long userId) {
        requireUser(userId);
        return radiusAssignmentRepository.findByUserId(userId);
    }

    @Override
    @Transactional(readOnly = true)
    public UserRadiusClient getRadiusAssignment(Long userId, Long clientId) {
        requireUser(userId);
        return radiusAssignmentRepository.findByUserIdAndClientId(userId, clientId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "User " + userId + " is not assigned to RADIUS client " + clientId));
    }

    @Override
    public UserRadiusClient putRadiusAssignment(Long userId, Long clientId, ClientAssignmentRequest request) {
        UserRadiusClient saved = executeUpsert(() -> {
            User user = requireUser(userId);
            RadiusClient client = requireRadiusClient(clientId);
            UserRadiusClient assignment = radiusAssignmentRepository.findByUserIdAndClientId(userId, clientId)
                    .orElseGet(() -> UserRadiusClient.builder().user(user).client(client).build());
            apply(request, assignment::setEnabled, assignment::setAuthMode);
            return radiusAssignmentRepository.saveAndFlush(assignment);
        });
        log.info("User id {} assigned to RADIUS client id {} (enabled={}, authMode={})",
                userId, clientId, saved.isEnabled(), saved.getAuthMode());
        return saved;
    }

    @Override
    @Transactional
    public void deleteRadiusAssignment(Long userId, Long clientId) {
        UserRadiusClient assignment = getRadiusAssignment(userId, clientId);
        radiusAssignmentRepository.delete(assignment);
        radiusAssignmentRepository.flush();
        log.info("User id {} unassigned from RADIUS client id {}", userId, clientId);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<UserRadiusClient> findEnabledRadiusAssignment(Long userId, Long clientId) {
        if (userId == null || clientId == null) {
            return Optional.empty();
        }
        return radiusAssignmentRepository.findByUserIdAndClientId(userId, clientId)
                .filter(UserRadiusClient::isEnabled);
    }

    // ---- OAuth 2.0 ---------------------------------------------------------------------------------

    @Override
    @Transactional(readOnly = true)
    public List<UserOAuthClient> getOAuthAssignments(Long userId) {
        requireUser(userId);
        return oauthAssignmentRepository.findByUserId(userId);
    }

    @Override
    @Transactional(readOnly = true)
    public UserOAuthClient getOAuthAssignment(Long userId, Long clientId) {
        requireUser(userId);
        return oauthAssignmentRepository.findByUserIdAndClientId(userId, clientId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "User " + userId + " is not assigned to OAuth client " + clientId));
    }

    @Override
    public UserOAuthClient putOAuthAssignment(Long userId, Long clientId, ClientAssignmentRequest request) {
        UserOAuthClient saved = executeUpsert(() -> {
            User user = requireUser(userId);
            OAuthClient client = requireOAuthClient(clientId);
            UserOAuthClient assignment = oauthAssignmentRepository.findByUserIdAndClientId(userId, clientId)
                    .orElseGet(() -> UserOAuthClient.builder().user(user).client(client).build());
            apply(request, assignment::setEnabled, assignment::setAuthMode);
            return oauthAssignmentRepository.saveAndFlush(assignment);
        });
        log.info("User id {} assigned to OAuth client id {} (enabled={}, authMode={})",
                userId, clientId, saved.isEnabled(), saved.getAuthMode());
        return saved;
    }

    @Override
    @Transactional
    public void deleteOAuthAssignment(Long userId, Long clientId) {
        UserOAuthClient assignment = getOAuthAssignment(userId, clientId);
        oauthAssignmentRepository.delete(assignment);
        oauthAssignmentRepository.flush();
        log.info("User id {} unassigned from OAuth client id {}", userId, clientId);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<UserOAuthClient> findEnabledOAuthAssignment(Long userId, Long clientId) {
        if (userId == null || clientId == null) {
            return Optional.empty();
        }
        return oauthAssignmentRepository.findByUserIdAndClientId(userId, clientId)
                .filter(UserOAuthClient::isEnabled);
    }

    // ---- bulk --------------------------------------------------------------------------------------

    @Override
    @Transactional(readOnly = true)
    public void validateAssignments(List<ClientAssignmentRequest> radiusClients,
                                    List<ClientAssignmentRequest> oauthClients) {
        if (radiusClients != null) {
            for (Long clientId : distinctClientIds(radiusClients, "radiusClients")) {
                requireRadiusClient(clientId, true);
            }
        }
        if (oauthClients != null) {
            for (Long clientId : distinctClientIds(oauthClients, "oauthClients")) {
                requireOAuthClient(clientId, true);
            }
        }
    }

    @Override
    @Transactional
    public void replaceAssignments(Long userId, List<ClientAssignmentRequest> radiusClients,
                                   List<ClientAssignmentRequest> oauthClients) {
        validateAssignments(radiusClients, oauthClients);
        User user = requireUser(userId);
        if (radiusClients != null) {
            Map<Long, UserRadiusClient> existing = new HashMap<>();
            for (UserRadiusClient a : radiusAssignmentRepository.findByUserId(userId)) {
                existing.put(a.getClientId(), a);
            }
            for (ClientAssignmentRequest request : radiusClients) {
                UserRadiusClient assignment = existing.remove(request.getClientId());
                if (assignment == null) {
                    assignment = UserRadiusClient.builder()
                            .user(user)
                            .client(requireRadiusClient(request.getClientId(), true))
                            .build();
                }
                apply(request, assignment::setEnabled, assignment::setAuthMode);
                radiusAssignmentRepository.save(assignment);
            }
            radiusAssignmentRepository.deleteAll(existing.values());
            radiusAssignmentRepository.flush();
        }
        if (oauthClients != null) {
            Map<Long, UserOAuthClient> existing = new HashMap<>();
            for (UserOAuthClient a : oauthAssignmentRepository.findByUserId(userId)) {
                existing.put(a.getClientId(), a);
            }
            for (ClientAssignmentRequest request : oauthClients) {
                UserOAuthClient assignment = existing.remove(request.getClientId());
                if (assignment == null) {
                    assignment = UserOAuthClient.builder()
                            .user(user)
                            .client(requireOAuthClient(request.getClientId(), true))
                            .build();
                }
                apply(request, assignment::setEnabled, assignment::setAuthMode);
                oauthAssignmentRepository.save(assignment);
            }
            oauthAssignmentRepository.deleteAll(existing.values());
            oauthAssignmentRepository.flush();
        }
    }

    @Override
    @Transactional(readOnly = true)
    public Map<Long, List<UserRadiusClient>> getRadiusAssignmentsByUserIds(Collection<Long> userIds) {
        if (userIds == null || userIds.isEmpty()) {
            return Map.of();
        }
        Map<Long, List<UserRadiusClient>> byUser = new LinkedHashMap<>();
        for (UserRadiusClient assignment : radiusAssignmentRepository.findByUserIdIn(userIds)) {
            byUser.computeIfAbsent(assignment.getUserId(), ignored -> new ArrayList<>()).add(assignment);
        }
        return byUser;
    }

    @Override
    @Transactional(readOnly = true)
    public Map<Long, List<UserOAuthClient>> getOAuthAssignmentsByUserIds(Collection<Long> userIds) {
        if (userIds == null || userIds.isEmpty()) {
            return Map.of();
        }
        Map<Long, List<UserOAuthClient>> byUser = new LinkedHashMap<>();
        for (UserOAuthClient assignment : oauthAssignmentRepository.findByUserIdIn(userIds)) {
            byUser.computeIfAbsent(assignment.getUserId(), ignored -> new ArrayList<>()).add(assignment);
        }
        return byUser;
    }

    @Override
    @Transactional
    public void deleteAllForUser(Long userId) {
        if (userId == null) {
            return;
        }
        radiusAssignmentRepository.deleteByUserId(userId);
        oauthAssignmentRepository.deleteByUserId(userId);
    }

    @Override
    @Transactional
    public void deleteAllForRadiusClient(Long clientId) {
        if (clientId != null) {
            radiusAssignmentRepository.deleteByClientId(clientId);
        }
    }

    @Override
    @Transactional
    public void deleteAllForOAuthClient(Long clientId) {
        if (clientId != null) {
            oauthAssignmentRepository.deleteByClientId(clientId);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public List<ClientSummaryResponse> listClients(ClientType type) {
        List<ClientSummaryResponse> result = new ArrayList<>();
        if (type == null || type == ClientType.RADIUS) {
            radiusClientRepository.findAll().stream()
                    .sorted(Comparator.comparing(RadiusClient::getId, Comparator.nullsLast(Comparator.naturalOrder())))
                    .map(ClientSummaryResponse::from)
                    .forEach(result::add);
        }
        if (type == null || type == ClientType.OAUTH2) {
            oauthClientRepository.findAll().stream()
                    .sorted(Comparator.comparing(OAuthClient::getId, Comparator.nullsLast(Comparator.naturalOrder())))
                    .map(ClientSummaryResponse::from)
                    .forEach(result::add);
        }
        return result;
    }

    // ---- helpers -----------------------------------------------------------------------------------

    private <T> T executeUpsert(Supplier<T> work) {
        if (transactionTemplate == null || TransactionSynchronizationManager.isActualTransactionActive()) {
            try {
                return work.get();
            } catch (DataIntegrityViolationException | OptimisticLockingFailureException e) {
                throw new ConflictException("Assignment was modified concurrently; retry the request");
            }
        }
        try {
            return transactionTemplate.execute(status -> work.get());
        } catch (DataIntegrityViolationException | OptimisticLockingFailureException firstRace) {
            try {
                return transactionTemplate.execute(status -> work.get());
            } catch (DataIntegrityViolationException | OptimisticLockingFailureException retryFailure) {
                throw new ConflictException("Assignment was modified concurrently; retry the request");
            }
        }
    }

    private static void apply(ClientAssignmentRequest request,
                              java.util.function.Consumer<Boolean> enabled,
                              java.util.function.Consumer<com.authprovider.entity.AuthMode> authMode) {
        // PUT semantics: the assignment is replaced; enabled defaults to true, authMode to inherit (null).
        enabled.accept(request == null || request.getEnabled() == null || request.getEnabled());
        authMode.accept(request == null ? null : request.getAuthMode());
    }

    private static Set<Long> distinctClientIds(List<ClientAssignmentRequest> requests, String field) {
        Set<Long> ids = new HashSet<>();
        for (ClientAssignmentRequest request : requests) {
            if (request == null || request.getClientId() == null) {
                throw new BadRequestException(field + ": clientId is required");
            }
            if (!ids.add(request.getClientId())) {
                throw new BadRequestException(field + ": duplicate clientId " + request.getClientId());
            }
        }
        return ids;
    }

    private User requireUser(Long userId) {
        if (userId == null) {
            throw new ResourceNotFoundException("User not found: null");
        }
        return userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + userId));
    }

    private RadiusClient requireRadiusClient(Long clientId) {
        return requireRadiusClient(clientId, false);
    }

    private RadiusClient requireRadiusClient(Long clientId, boolean badRequest) {
        Optional<RadiusClient> client = clientId == null ? Optional.empty() : radiusClientRepository.findById(clientId);
        if (client.isEmpty()) {
            String message = "RADIUS client not found: " + clientId;
            throw badRequest ? new BadRequestException(message) : new ResourceNotFoundException(message);
        }
        return client.get();
    }

    private OAuthClient requireOAuthClient(Long clientId) {
        return requireOAuthClient(clientId, false);
    }

    private OAuthClient requireOAuthClient(Long clientId, boolean badRequest) {
        Optional<OAuthClient> client = clientId == null ? Optional.empty() : oauthClientRepository.findById(clientId);
        if (client.isEmpty()) {
            String message = "OAuth client not found: " + clientId;
            throw badRequest ? new BadRequestException(message) : new ResourceNotFoundException(message);
        }
        return client.get();
    }
}
