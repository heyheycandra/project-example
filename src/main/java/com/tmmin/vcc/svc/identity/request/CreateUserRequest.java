package com.tmmin.vcc.svc.identity.request;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CreateUserRequest {
	private String userName;
	private String userTypeCd;
	private String personName;
	private String birthDt;
	private String gender;
	private String genderCd;
	private String idCardNo;
	private String email;
	private String emailExternal;
	private String mobileNo;
	private String job;
	private Boolean regVAFlag;
	private String regVADt;
	private Boolean changeDefaultPinFlag;
	private String changeDefaultPinDt;
	private String oid;
	private Boolean blockedFlag;

}
