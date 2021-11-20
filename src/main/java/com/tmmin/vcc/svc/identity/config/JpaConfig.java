package com.tmmin.vcc.svc.identity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration
@EnableJpaRepositories(value = "com.tmmin.vcc.svc.identity.repository")
public class JpaConfig {
}
