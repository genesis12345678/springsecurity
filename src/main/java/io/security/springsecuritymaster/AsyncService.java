package io.security.springsecuritymaster;

import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class AsyncService {

    @Async
    public void asyncMethod() {
        SecurityContext context = SecurityContextHolder.getContextHolderStrategy().getContext();
        log.info("context = {}", context);
        log.info("Child Thread = {}", Thread.currentThread().getName());
    }
}
