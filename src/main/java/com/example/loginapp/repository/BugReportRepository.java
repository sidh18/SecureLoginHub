package com.example.loginapp.repository;

import com.example.loginapp.model.BugReport;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface BugReportRepository extends JpaRepository<BugReport, Long> {

    /**
     * Finds all bug reports and eagerly fetches the related organization and user
     * to prevent LazyInitializationException in the controller.
     */
    @Query("SELECT b FROM BugReport b JOIN FETCH b.organization JOIN FETCH b.reportedBy ORDER BY b.createdAt DESC")
    List<BugReport> findAllWithDetails();
}