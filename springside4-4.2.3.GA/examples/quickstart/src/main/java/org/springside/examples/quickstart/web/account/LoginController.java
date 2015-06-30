/*******************************************************************************
 * Copyright (c) 2005, 2014 springside.github.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *******************************************************************************/
package org.springside.examples.quickstart.web.account;


import java.io.IOException;
import java.text.SimpleDateFormat;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springside.examples.quickstart.service.account.AccountService;
import org.springside.examples.quickstart.service.account.ShiroDbRealm;

import weibo4j.Oauth;
import weibo4j.Users;
import weibo4j.http.AccessToken;
import weibo4j.model.User;

import com.qq.connect.QQConnectException;
import com.qq.connect.api.OpenID;
import com.qq.connect.api.qzone.UserInfo;
import com.qq.connect.javabeans.qzone.UserInfoBean;

/**
 * LoginController负责打开登录页面(GET请求)和登录出错页面(POST请求)，
 * 
 * 真正登录的POST请求由Filter完成,
 * 
 * @author calvin
 * eclipse test git change
 */
@Controller
@RequestMapping(value = "/login")
public class LoginController {
	
	private static Logger logger = LoggerFactory.getLogger(LoginController.class);
	private static final int QQ    = 1;
	private static final int WEIBO = 2;
	
	@Autowired
	private AccountService accountService;
	
	@Autowired
	private ShiroDbRealm shiroDbRealm;
	
	@RequestMapping(method = RequestMethod.GET)	
	public String login() {
		return "account/login";
	}

	@RequestMapping(method = RequestMethod.POST)
	public String fail(@RequestParam(FormAuthenticationFilter.DEFAULT_USERNAME_PARAM) String userName, Model model) {
		model.addAttribute(FormAuthenticationFilter.DEFAULT_USERNAME_PARAM, userName);
		return "account/login";
	}
	
	@RequestMapping(value = "/weibo", method = RequestMethod.GET)
	public String weiboLogin(HttpServletRequest request,HttpServletResponse response, ModelMap model) throws Exception {
		logger.info("you want login with weibo");
		response.setContentType("text/html;charset=utf-8");
		String url = new weibo4j.Oauth().authorize("code", "", "");
		return "redirect:" + url;
	}
	
	@RequestMapping(value = "/qq",method = RequestMethod.GET)
	public String qqLogin(HttpServletRequest request,HttpServletResponse response,ModelMap model){
		
		String url = null;
		try {
			url = new  com.qq.connect.oauth.Oauth().getAuthorizeURL(request);
		} 
		catch (QQConnectException e) {
			logger.error(e.getMessage(),e);
		}
		return "redirect:" + url;
	}
	
	@RequestMapping(value = "/qq/callback",method = RequestMethod.GET)
	public String qqCallback(HttpServletRequest request,HttpServletResponse response,ModelMap model) throws IOException{
		response.setContentType("text/html;charset=utf-8");
        try {
        	com.qq.connect.javabeans.AccessToken accessTokenObj = new com.qq.connect.oauth.Oauth().getAccessTokenByRequest(request);
            String accessToken = null;
            String openID      = null;
            long tokenExpireIn = 0L;
            if (accessTokenObj.getAccessToken().equals("")) {
//                我们的网站被CSRF攻击了或者用户取消了授权
//                做一些数据统计工作
                logger.info("qq third login 没有获取到响应参数");
            } else {
                accessToken = accessTokenObj.getAccessToken();
                tokenExpireIn = accessTokenObj.getExpireIn();

                // 利用获取到的accessToken 去获取当前用的openid -------- start
                OpenID openIDObj =  new OpenID(accessToken);
                openID = openIDObj.getUserOpenID();

                logger.info("QQ third login openId:" + openID );
                request.getSession().setAttribute("qq_openid", openID);
                request.getSession().setAttribute("qq_access_token", accessToken);
                request.getSession().setAttribute("qq_token_expirein", String.valueOf(tokenExpireIn));
                // 利用获取到的accessToken 去获取当前用户的openid --------- end

                logger.info("<p> start --------------利用获取到的accessToken,openid 去获取用户在Qzone的昵称等信息 --------------- start </p>");
                UserInfo qzoneUserInfo = new UserInfo(accessToken, openID);
                UserInfoBean userInfoBean = qzoneUserInfo.getUserInfo();
                logger.info(userInfoBean.toString());
                thirdLogin(openID,QQ);
            }
        } catch (QQConnectException e) {
        	logger.error(e.getMessage(),e);
        }
		return "redirect:http://www.gintong.com/task";
	}
	
	@RequestMapping(value = "/weibo/callback")
	public String weiboCallback(HttpServletRequest request,HttpServletResponse response, ModelMap model) throws Exception {
		response.setContentType("text/html; charset=utf-8");
		String accessToken = null;
		String uid = null;
		String tokenExpireIn = null;
		String code = request.getParameter("code");
		logger.info("thrid login weibo user  code:"+code);
		try {
			AccessToken accessTokenObj = (new Oauth()).getAccessTokenByCode(code);
			if (accessTokenObj.getAccessToken().equals("")) {
				// 我们的网站被CSRF攻击了或者用户取消了授权
				// 做一些数据统计工作
				logger.info("没有获取到响应参数");
				model.addAttribute("code", "-6003");
				return "redirect:/login";
			} else {
				accessToken   = accessTokenObj.getAccessToken();
				//new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Long.valueOf(accessTokenObj.getExpireIn())*1000L);
				tokenExpireIn = accessTokenObj.getExpireIn();
				uid           = accessTokenObj.getUid();
				logger.info("thrid login weibo user accessToken: "+accessToken);
				logger.info("thrid login weibo user tokenExpireIn: "+tokenExpireIn);
				logger.info("thrid login weibo user uid: "+uid);
				
				/**
				   Account account = new Account();
				   account.client.setToken(accessToken);
				   JSONObject json_uid = account.getUid() ; // 利用获取到的accessToken 去获取当前用的openid -------- start
				   uid = json_uid.toString().split(":")[1].replace("}", "");
				   logger.info(uid);
				*/

				Users um = new Users();
				um.client.setToken(accessToken);
				User user = um.showUserById(uid);
				logger.info(user.toString());
				thirdLogin(uid,WEIBO);
			}
		} catch (Exception e) {
			logger.error(e.getMessage(),e);
		}
		return "redirect:http://www.gintong.com/task";
	}

	private void updateStatusThirdLogin(org.springside.examples.quickstart.entity.User u) {
		Subject subject = SecurityUtils.getSubject();
		UsernamePasswordToken token = new UsernamePasswordToken(u.getLoginName(),"admin");
		subject.login(token);
	}
	
	private void thirdLogin(String uid,int loginType){
		org.springside.examples.quickstart.entity.User user = accountService.findUserThirdLoginByOpenId(uid, loginType);
		if(user != null){
			updateStatusThirdLogin(user);
		}
		else{
			org.springside.examples.quickstart.entity.User local_user= accountService.findUserByLoginName("admin");
			if(loginType == QQ) {
				local_user.setQqLogin(uid);
			}
			else if (loginType == WEIBO){
				local_user.setWeiboLogin(uid);
			}
			accountService.updateUser(local_user);
			updateStatusThirdLogin(local_user);
		}
	}
	
}
