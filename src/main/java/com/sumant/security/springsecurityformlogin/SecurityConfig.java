package com.sumant.security.springsecurityformlogin;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

//@Configuration
//@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain (HttpSecurity http) throws Exception {

        http.authorizeHttpRequests( (authorize) -> authorize.anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .formLogin(Customizer.withDefaults());

        return http.build();

    }

    /**
     * In memory version of UserDetailsService
     * This should only be used for development purposes as it is not a safe way.
     *
     * UserDetails-based authentication is used by Spring Security
     * when it is configured to accept a username/password for authentication.
     * @return
     */
//    @Bean
//    public UserDetailsService userDetailsService(){
//        UserDetails userDetails = User.withDefaultPasswordEncoder()
//                .username("admin")
//                .password("AlwaysBeKind!23")
//                .roles("ADMIN")
//                .build();
//
//        return new InMemoryUserDetailsManager(userDetails);
//    }

    /**
     * Create a data source using Embedded Database and use the script provided by
     * JdbcDaoImpl to create default schema.
     * @return
     */
    @Bean
    public DataSource dataSource(){
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        UserDetails admin = User.builder()
                .username("administrator")
                .password("{bcrypt}$2a$10$2gnHWCp7LCJVTDJdOw6nsOtcEt63VCrQG3WmE3QozC8Nu2HL00F.m")
                .roles("ADMIN")
                .build();

        JdbcUserDetailsManager userDetails = new JdbcUserDetailsManager(dataSource);
        userDetails.createUser(admin);
        return userDetails;
    }

}
