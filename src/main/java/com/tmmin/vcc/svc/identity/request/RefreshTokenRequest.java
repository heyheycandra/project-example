package com.tmmin.vcc.svc.identity.request;

import javax.validation.constraints.NotBlank;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RefreshTokenRequest {
	@NotBlank
	private String refreshToken;
	@NotBlank
	private String username;

}
