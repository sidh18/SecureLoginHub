package com.example.loginapp.config;

import com.example.loginapp.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.http.HttpMethod;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Autowired
    private TenantIdentifierFilter tenantIdentifierFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    @Order(1) // Give this filter chain a lower priority than the API one
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints
                        .requestMatchers("/", "/signup", "/register").permitAll()
                        .requestMatchers("/sso/**").permitAll()
                        .requestMatchers("/saml/**").permitAll()
                        .requestMatchers("/oauth/**").permitAll()

                        // Public APIs for dynamic login page
                        .requestMatchers("/api/test").permitAll()
                        .requestMatchers("/api/tenant/info").permitAll()
                        .requestMatchers("/api/sso-configs/tenant","/api/auth/check-username",
                                "/api/auth/check-subdomain" ).permitAll()

                        .requestMatchers(HttpMethod.POST, "/api/bugs").hasAnyRole("ADMIN", "USER")
                        .requestMatchers(HttpMethod.GET, "/api/bugs").hasRole("SUPER_ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/api/bugs/*", "/api/bugs/**").hasRole("SUPER_ADMIN")

                        // --- FIX: ---
                        // Allow public access to the new tenant-aware API login/register endpoints
                        .requestMatchers("/api/auth/login").permitAll()
                        .requestMatchers("/api/auth/signup").permitAll()
                        // --- END FIX ---

                        // --- NEW ROLE-BASED RULES ---
                        // Tenant Admin paths
                        .requestMatchers("/admin/dashboard").hasRole("ADMIN")
                        .requestMatchers("/admin/api/**").hasRole("ADMIN")

                        // Superadmin paths
                        .requestMatchers("/superadmin/dashboard").hasRole("SUPER_ADMIN")
                        .requestMatchers("/superadmin/api/**").hasRole("SUPER_ADMIN")

                        // Secured user endpoints
                        .requestMatchers("/home").hasAnyRole("USER", "ADMIN", "SUPER_ADMIN")
                        .requestMatchers("/api/**").authenticated() // General API fallback
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        // We use IF_REQUIRED to allow sessions for form login
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                )
                .formLogin(form -> form
                        .loginPage("/")
                        .loginProcessingUrl("/login") // This is for the "superadmin" form
                        .defaultSuccessUrl("/home", true)
                        .successHandler((req, res, auth) -> {
                            // --- UPDATED FOR MULTI-TENANCY ---
                            boolean isSuperAdmin = auth.getAuthorities().stream()
                                    .anyMatch(a -> a.getAuthority().equals("ROLE_SUPER_ADMIN"));
                            boolean isAdmin = auth.getAuthorities().stream()
                                    .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

                            if (isSuperAdmin) {
                                res.sendRedirect("/superadmin/dashboard");
                            } else if (isAdmin) {
                                res.sendRedirect("/admin/dashboard");
                            } else {
                                res.sendRedirect("/home");
                            }
                        })
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/")
                        .permitAll()
                )
                .authenticationProvider(authenticationProvider())

                // --- FIX: Add JWT filter first, then add Tenant filter before it ---
                // This adds the JWT filter to the chain, relative to Spring's known filter
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                // This NOW works, as JwtAuthenticationFilter.class is a known anchor
                .addFilterBefore(tenantIdentifierFilter, JwtAuthenticationFilter.class);

        return http.build();
    }
}

