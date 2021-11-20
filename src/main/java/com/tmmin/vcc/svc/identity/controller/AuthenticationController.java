package com.tmmin.vcc.svc.identity.controller;

import com.tmmin.vcc.lib.core.controller.BaseController;
import com.tmmin.vcc.lib.core.response.Response;
import com.tmmin.vcc.lib.core.util.ResponseUtil;
import com.tmmin.vcc.lib.core.vo.User;
import com.tmmin.vcc.svc.identity.request.RefreshTokenRequest;
import com.tmmin.vcc.svc.identity.response.LoginResponse;
import com.tmmin.vcc.svc.identity.service.AuthenticationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;

@Slf4j
@RestController
public class AuthenticationController extends BaseController {
    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private ResponseUtil responseUtil;

    @PostMapping("login")
    public Response<LoginResponse> login(@RequestBody @Valid User user) {
        log.debug("Login with user [{}]", user);

        LoginResponse loginResponse = authenticationService.login(user.getUsername(), user.getPassword());

        return responseUtil.generateResponseSuccess(loginResponse);
    }

    @PostMapping("logout")
    public Response<Object> logout(Authentication authentication,
                                   @RequestHeader("Authorization") @NotBlank String authorizationString) {
        log.debug("Logout with user [{}], authorizationString [{}]", authentication.getPrincipal(),
                authorizationString);

        authenticationService.logout(authorizationString);

        return responseUtil.generateResponseSuccess();
    }

    @PostMapping("refresh-token")
    public Response<LoginResponse> refreshToken(@RequestBody @Valid RefreshTokenRequest data) {
        log.debug("Refresh token with data [{}}", data);

        LoginResponse loginResponse = authenticationService.refreshToken(data);

        return responseUtil.generateResponseSuccess(loginResponse);
    }
}
