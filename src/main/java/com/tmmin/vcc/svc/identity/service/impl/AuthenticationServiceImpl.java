package com.tmmin.vcc.svc.identity.service.impl;

import com.tmmin.vcc.lib.core.entity.TokenBlacklist;
import com.tmmin.vcc.lib.core.exception.BusinessException;
import com.tmmin.vcc.lib.core.repository.UserRepository;
import com.tmmin.vcc.lib.core.service.TokenBlacklistService;
import com.tmmin.vcc.lib.core.util.JwtUtil;
import com.tmmin.vcc.lib.core.vo.JwtInfo;
import com.tmmin.vcc.lib.core.vo.UserInfo;
import com.tmmin.vcc.svc.identity.request.RefreshTokenRequest;
import com.tmmin.vcc.svc.identity.response.LoginResponse;
import com.tmmin.vcc.svc.identity.service.AuthenticationService;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {
    @Autowired
    TokenBlacklistService tokenBlacklistService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private AuthenticationManager authenticationManager;
    
    @Autowired
    UserRepository userRepository;

    @Override
    public LoginResponse login(String username, String password) {
    	
    	byte[] decodedPass = Base64.getDecoder().decode(password);
    	password = new String(decodedPass, StandardCharsets.UTF_8);
        
        try {
            Authentication authenticate =
                    authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (BadCredentialsException ex) {
            throw new BusinessException("COMMNERR00008");
        }

        return this.generateLoginResponse(username);
    }

    @Override
    @Transactional
    public void logout(String authorizationString) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserInfo userInfo = (UserInfo) authentication.getPrincipal();
        String accessToken = jwtUtil.getAccessToken(authorizationString);

        TokenBlacklist tokenBlacklistOld = tokenBlacklistService.getTokenBlacklistByToken(accessToken);
        if (tokenBlacklistOld != null) {
            return;
        }

        TokenBlacklist tokenBlacklist = new TokenBlacklist();
        tokenBlacklist.setToken(accessToken);
        tokenBlacklistService.create(tokenBlacklist, userInfo.getUsername());
    }

    @Override
    public LoginResponse refreshToken(RefreshTokenRequest data) throws BusinessException {
        String username = jwtUtil.parseRefreshToken(data.getRefreshToken()).getSubject();

        if (!data.getUsername().equals(username)) {
            throw new BusinessException("mesgId", "parameter username should same with subject in refresh token");
        }

        return this.generateLoginResponse(username);
    }

    public Boolean isTokenBlacklisted(String token) {

        return tokenBlacklistService.getTokenBlacklistByToken(token) != null;
    }

    private LoginResponse generateLoginResponse(String username) {
        JwtInfo accessTokenInfo = jwtUtil.generateAccessToken(username);
        JwtInfo refreshTokenInfo = jwtUtil.generateRefreshToken(username);

        LoginResponse response = new LoginResponse();
        response.setTokenType(jwtUtil.getTokenType());

        response.setAccessToken(accessTokenInfo.getToken());
        response.setAccessTokenExpDate(accessTokenInfo.getExpiration());
        response.setAccessTokenAge(accessTokenInfo.getAge());

        response.setRefreshToken(refreshTokenInfo.getToken());
        response.setRefreshTokenExpDate(refreshTokenInfo.getExpiration());
        response.setRefreshTokenAge(refreshTokenInfo.getAge());

        return response;
    }
}
