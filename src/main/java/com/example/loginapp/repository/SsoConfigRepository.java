// SsoConfigRepository.java
package com.example.loginapp.repository;

import com.example.loginapp.model.SsoConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SsoConfigRepository extends JpaRepository<SsoConfig, Long> {

    Optional<SsoConfig> findFirstByOrderByIdDesc();
}