package com.tmmin.vcc.svc.identity.response;

import java.util.Date;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.tmmin.vcc.svc.identity.constants.Constants;

import lombok.Data;

@Data
public class LoginResponse {
	private String tokenType;
	private String accessToken;
	@JsonFormat(pattern = Constants.DATE_TIME_FORMAT)
	private Date accessTokenExpDate;
	private Integer accessTokenAge;
	private String refreshToken;
	@JsonFormat(pattern = Constants.DATE_TIME_FORMAT)
	private Date refreshTokenExpDate;
	private Integer refreshTokenAge;

}
