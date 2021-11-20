package com.tmmin.vcc.svc.identity.service;

import com.tmmin.vcc.lib.core.exception.BusinessException;
import com.tmmin.vcc.lib.core.service.BaseService;
import com.tmmin.vcc.svc.identity.request.RefreshTokenRequest;
import com.tmmin.vcc.svc.identity.response.LoginResponse;

public interface AuthenticationService extends BaseService {
    LoginResponse login(String username, String password);

    void logout(String token);

    LoginResponse refreshToken(RefreshTokenRequest data) throws BusinessException;

    Boolean isTokenBlacklisted(String authorizationString);
}
