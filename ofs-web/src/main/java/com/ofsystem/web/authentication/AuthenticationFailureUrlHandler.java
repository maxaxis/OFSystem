package com.ofsystem.web.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

public class AuthenticationFailureUrlHandler implements
		AuthenticationFailureHandler {

	@Override
	public void onAuthenticationFailure(HttpServletRequest req,
			HttpServletResponse resp, AuthenticationException exception)
			throws IOException, ServletException {
		String redirectUrl = req.getParameter("redirectUrl");
		req.getSession(true).invalidate();
		if ((redirectUrl != null && !redirectUrl.equals(""))) {
			//req.getSession().setAttribute("error", "Invalid Login Credentials");
			resp.sendRedirect("/login?error=true&redirectUrl=" + redirectUrl);
		}else {
			//req.getSession().setAttribute("error", "Invalid Login Credentials");
			resp.sendRedirect("/login?error=true");
		}
	}
}
