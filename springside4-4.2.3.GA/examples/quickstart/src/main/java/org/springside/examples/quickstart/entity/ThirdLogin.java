package org.springside.examples.quickstart.entity;

import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name="ss_login_third")
public class ThirdLogin extends IdEntity {
	
	private String openid;
	private String accessToken;
	private String expiresDay;
	private int loginType;

	public String getOpenid() {
		return openid;
	}
	public void setOpenid(String openid) {
		this.openid = openid;
	}
	public String getAccessToken() {
		return accessToken;
	}
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}
	public String getExpiresDay() {
		return expiresDay;
	}
	public void setExpiresDay(String expiresDay) {
		this.expiresDay = expiresDay;
	}
	public int getLoginType() {
		return loginType;
	}
	public void setLoginType(int loginType) {
		this.loginType = loginType;
	}
	
	

}
