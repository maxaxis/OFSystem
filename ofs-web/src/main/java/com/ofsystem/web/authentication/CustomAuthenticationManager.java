package com.ofsystem.web.authentication;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.log4j.Logger;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.encoding.ShaPasswordEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * A custom authentication manager that allows access if the user details exist
 * in the database and if the username and password are not the same. Otherwise,
 * throw a {@link BadCredentialsException}
 */
public class CustomAuthenticationManager implements AuthenticationManager {
	private static Logger LOGGER = Logger.getLogger(CustomAuthenticationManager.class.getName());
	private static String USERNAME = "adminofs";
	private static String PASSWORD = "OFS1234";
	private static String ROLE = "ADMIN";

	// We need an ShaPasswordEncoder encoder since our passwords in the database are ShaPasswordEncoder encoded.
	private ShaPasswordEncoder passwordEncoder = new ShaPasswordEncoder(256);

	public Authentication authenticate(Authentication auth) throws AuthenticationException {
		LOGGER.info("Performing custom authentication");
		
		if (auth != null && auth.getName() != null && !auth.getName().equals("")) {
			try {
				// Retrieve user details from database
				String username = auth.getName();
				String pwd = (String) auth.getCredentials();
				if(pwd!=null){
					passwordEncoder.encodePassword(pwd, username);
					if (passwordEncoder.encodePassword(pwd, username).equals(passwordEncoder.encodePassword(PASSWORD, USERNAME))) {
						LOGGER.info("User credentials are fine");
						return new UsernamePasswordAuthenticationToken(auth.getName(), auth.getCredentials(), getAuthorities(ROLE));
					}else {
						LOGGER.info("Incorrect Password");
						throw new BadCredentialsException("Please enter valid username and password");
					}		
				}else{
					LOGGER.info("User not authorized");
					throw new BadCredentialsException("Please enter valid username and password");
				}
			} catch (Exception e) {
				LOGGER.error("User does not exists!", e);
				throw new BadCredentialsException("Please enter valid username and password");
			}
		} else {
			LOGGER.info("Username and Password are required");
			throw new BadCredentialsException("Please enter valid username and password");
		}
	}

	/**
	 * Retrieves the correct ROLE type depending on the access level, where
	 * access level is an Integer. Basically, this interprets the access value
	 * whether it's for a regular user or admin.
	 * 
	 * @param access
	 *            an integer value representing the access of the user
	 * @return collection of granted authorities
	 */
	public Collection<GrantedAuthority> getAuthorities(String role) {
		// Create a list of grants for this user
		List<GrantedAuthority> authList = new ArrayList<GrantedAuthority>(0);
		// Check if this user has admin access
		if (role == ROLE) {
			LOGGER.info("Grant ROLE_ADMIN to this user");
			authList.add(new SimpleGrantedAuthority(ROLE));
		}
		// Return list of granted authorities
		return authList;
	}
}
