package com.tmmin.vcc.svc.identity.config;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@EntityScan("com.tmmin.vcc.svc.identity.entity")
public class EntityConfig {

}
