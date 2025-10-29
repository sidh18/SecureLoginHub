package com.example.loginapp.model;

import jakarta.persistence.*;

@Entity
@Table(name = "users")
public class user {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column
    private String email;

    @Column
    private String firstName;

    @Column
    private String lastName;

    @Column(nullable = false)
    private String role = "USER"; // USER or ADMIN

    @Column
    private Boolean active = true;

    @Column
    private java.time.LocalDateTime createdAt;

    @Column
    private String createdVia; // REGULAR or SSO

    public user() {
        this.createdAt = java.time.LocalDateTime.now();
        this.createdVia = "REGULAR";
    }

    public user(String username, String password) {
        this.username = username;
        this.password = password;
        this.role = "USER";
        this.active = true;
        this.createdAt = java.time.LocalDateTime.now();
        this.createdVia = "REGULAR";
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

//    public String getEmail() { return email; }
//    public void setEmail(String email) { this.email = email; }
//
//    public String getFirstName() { return firstName; }
//    public void setFirstName(String firstName) { this.firstName = firstName; }
//
//    public String getLastName() { return lastName; }
//    public void setLastName(String lastName) { this.lastName = lastName; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }

    public Boolean getActive() { return active; }
    public void setActive(Boolean active) { this.active = active; }

    public java.time.LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(java.time.LocalDateTime createdAt) { this.createdAt = createdAt; }

    public String getCreatedVia() { return createdVia; }
    public void setCreatedVia(String createdVia) { this.createdVia = createdVia; }
}