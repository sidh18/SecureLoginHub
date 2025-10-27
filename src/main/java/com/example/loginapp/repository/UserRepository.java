package com.example.loginapp.repository;

import com.example.loginapp.model.user;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<user, Long> {
    user findByUsername(String username);
}