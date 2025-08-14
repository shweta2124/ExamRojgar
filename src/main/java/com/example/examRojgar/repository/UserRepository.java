package com.example.examRojgar.repository;

import com.example.examRojgar.entity.UserData;
import com.example.examRojgar.enums.Role;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserData, Long> {
    Optional<UserData> findByUsername(String username);

    Optional<UserData> findByUsernameAndRole(String username, Role role);
}
