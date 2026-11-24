package com.authprovider.service;

import com.authprovider.dto.ClientAssignmentRequest;
import com.authprovider.dto.ClientSummaryResponse;
import com.authprovider.entity.ClientType;
import com.authprovider.entity.UserOAuthClient;
import com.authprovider.entity.UserRadiusClient;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Management and enforcement of user to client assignments. A user may only authenticate, validate an OTP
 * or pre-authenticate MFA through a RADIUS or OAuth 2.0 client it holds an <em>enabled</em> assignment for.
 */
public interface UserClientAssignmentService {

    // ---- RADIUS ------------------------------------------------------------------------------------

    List<UserRadiusClient> getRadiusAssignments(Long userId);

    UserRadiusClient getRadiusAssignment(Long userId, Long clientId);

    /** Creates or replaces the assignment of user {@code userId} to RADIUS client {@code clientId}. */
    UserRadiusClient putRadiusAssignment(Long userId, Long clientId, ClientAssignmentRequest request);

    void deleteRadiusAssignment(Long userId, Long clientId);

    /** The enabled assignment of the user to the RADIUS client, if any. */
    Optional<UserRadiusClient> findEnabledRadiusAssignment(Long userId, Long clientId);

    // ---- OAuth 2.0 ---------------------------------------------------------------------------------

    List<UserOAuthClient> getOAuthAssignments(Long userId);

    UserOAuthClient getOAuthAssignment(Long userId, Long clientId);

    /** Creates or replaces the assignment of user {@code userId} to OAuth 2.0 client {@code clientId}. */
    UserOAuthClient putOAuthAssignment(Long userId, Long clientId, ClientAssignmentRequest request);

    void deleteOAuthAssignment(Long userId, Long clientId);

    /** The enabled assignment of the user to the OAuth 2.0 client, if any. */
    Optional<UserOAuthClient> findEnabledOAuthAssignment(Long userId, Long clientId);

    // ---- bulk --------------------------------------------------------------------------------------

    /**
     * Validates assignment lists of a user payload (client ids present, existing and unique) without
     * changing anything. {@code null} lists are ignored.
     */
    void validateAssignments(List<ClientAssignmentRequest> radiusClients, List<ClientAssignmentRequest> oauthClients);

    /**
     * Replaces the assignments of a user with the given lists. A {@code null} list leaves the corresponding
     * assignments unchanged; an empty list removes them all.
     */
    void replaceAssignments(Long userId, List<ClientAssignmentRequest> radiusClients,
                            List<ClientAssignmentRequest> oauthClients);

    Map<Long, List<UserRadiusClient>> getRadiusAssignmentsByUserIds(Collection<Long> userIds);

    Map<Long, List<UserOAuthClient>> getOAuthAssignmentsByUserIds(Collection<Long> userIds);

    void deleteAllForUser(Long userId);

    void deleteAllForRadiusClient(Long clientId);

    void deleteAllForOAuthClient(Long clientId);

    /** Lists all clients of every type (or only {@code type} when not {@code null}), without secrets. */
    List<ClientSummaryResponse> listClients(ClientType type);
}
