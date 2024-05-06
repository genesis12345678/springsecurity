package io.security.springsecuritymaster;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class SessionInfoService {

    private final SessionRegistry sessionRegistry;

    public void sessionInfo() {
        for (Object principal : sessionRegistry.getAllPrincipals()) {
            List<SessionInformation> allSessions = sessionRegistry.getAllSessions(principal, false);
            for (SessionInformation session : allSessions) {
                log.info("사용자 = {}", principal);
                log.info("세션 ID = {}", session.getSessionId());
                log.info("최종 요청 시간 = {}", session.getLastRequest());
                log.info("----------------------------------------------");
            }
        }
    }
}
