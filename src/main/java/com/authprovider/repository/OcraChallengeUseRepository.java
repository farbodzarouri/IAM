package com.authprovider.repository;

import com.authprovider.entity.OcraChallengeUse;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public interface OcraChallengeUseRepository extends JpaRepository<OcraChallengeUse, Long> {

    boolean existsBySubjectKeyAndChallengeHash(String subjectKey, String challengeHash);

    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from OcraChallengeUse u where u.subjectKey = :subjectKey")
    int deleteBySubjectKey(@Param("subjectKey") String subjectKey);
}
