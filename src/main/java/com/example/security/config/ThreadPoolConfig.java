package com.example.security.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;

@Configuration
@EnableAsync
@Slf4j
public class ThreadPoolConfig {

    @Value("${application.async.corepoolsize}")
    private int corePoolSize;

    @Value("${application.async.maxpoolsize}")
    private int maxPoolSize;


    @Bean(name = "asyncTaskExecutor")
    public Executor asyncTaskExecutor() {
        log.info("Creating Async Task Executor for AsyncAPI to serve request in parallel threads");
        final ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(corePoolSize);
        executor.setMaxPoolSize(maxPoolSize);
        executor.setQueueCapacity(10); //Keep this commented else throws error if queue is full.
        executor.setThreadNamePrefix("asyncexe-");
        executor.initialize();
        return executor;
    }
}
