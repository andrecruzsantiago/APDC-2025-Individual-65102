package pt.unl.fct.di.apdc.firstwebapp.util;

import java.security.SecureRandom;
import java.util.Date;

public class AuthToken {
	
	public String username;
	public Date validFrom;
	public Date validTo;
	public String validator;
	
	public AuthToken(String user) {
		username = user;
		validFrom = new Date();
		validTo = new Date(validFrom.getTime() + 1000 * 60 * 5);
		validator = Long.toHexString(new SecureRandom().nextLong());
	}

	
}
