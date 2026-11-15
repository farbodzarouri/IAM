package com.authprovider.repository;

import com.authprovider.entity.AuthAuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AuthAuditLogRepository extends JpaRepository<AuthAuditLog, Long> {
    List<AuthAuditLog> findByUsernameOrderByIdAsc(String username);

    List<AuthAuditLog> findByChannelOrderByIdAsc(AuthAuditLog.Channel channel);

    List<AuthAuditLog> findAllByOrderByIdAsc();
}
