package com.example.loginapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

// Remove all the javax.net.ssl and java.security imports
// We are back to a clean, secure application.

@SpringBootApplication
public class LoginAppApplication extends SpringBootServletInitializer {

    /**
     * This is the standard main method for running as a JAR.
     */
    public static void main(String[] args) {
        SpringApplication.run(LoginAppApplication.class, args);
    }

    /**
     * This new method is required to run as a WAR.
     * It tells Spring Boot how to configure the application when
     * it's started by an external servlet container.
     */
    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
        return builder.sources(LoginAppApplication.class);
    }
}
