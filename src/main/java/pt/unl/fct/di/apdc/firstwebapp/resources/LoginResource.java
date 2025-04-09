package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.util.logging.Logger;

import com.google.appengine.repackaged.org.apache.commons.codec.digest.DigestUtils;
import com.google.cloud.datastore.*;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

import pt.unl.fct.di.apdc.firstwebapp.util.LoginInfo;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

@Path("/login")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LoginResource {
	
	private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
	private final Gson g = new Gson();
	private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
	
	public LoginResource() {
		
	}
	
	@POST
	@Path("/")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response doLogin(LoginInfo data) {
		LOG.fine("Attempting to login: " + data.username);

		if (data.username == null || data.password == null) {
			return Response.status(Status.BAD_REQUEST).entity("Username/Email and password are required.").build();
		}

		Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
		Entity userEntity = datastore.get(userKey);

		if (userEntity == null) {
			Query<Entity> query = Query.newEntityQueryBuilder()
					.setKind("User")
					.setFilter(StructuredQuery.PropertyFilter.eq("email", data.username))
					.build();

			var existingUser = datastore.run(query);
			if (existingUser.hasNext()) {
				userEntity = existingUser.next();
			}
		}

		if (userEntity == null) {
			return Response.status(Status.NOT_FOUND).entity("User not found.").build();
		}

		String storedPassword = userEntity.getString("password");
		if (!storedPassword.equals(DigestUtils.sha512Hex(data.password))) {
			return Response.status(Status.UNAUTHORIZED).entity("Invalid password.").build();
		}

		String realUsername = userEntity.getKey().getName();
		AuthToken token = new AuthToken(realUsername);
		Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User",realUsername)).setKind("Token").newKey(token.validator);

		Entity tokenEntity = Entity.newBuilder(tokenKey)
				.set("validfrom", token.validFrom.toString())
				.set("validTo", token.validTo.toString())
				.set("user", token.username)
				.build();

		datastore.put(tokenEntity);

		String role = userEntity.getString("role");
		String URL = "";

		switch(role){
			case "ADMIN":
				URL = "/adminPage.html";
				break;
			case "BACKOFFICE":
				URL = "/backofficePage.html";
				break;
			case "ENDUSER":
				URL = "/enduserPage.html";
				break;
			case "PARTNER":
				URL = "/partnerPage.html";
				break;
		}

		JsonObject responseJson = new JsonObject();
		responseJson.add("token", g.toJsonTree(token));
		responseJson.addProperty("link", URL);

		return Response.ok(responseJson.toString())
				.build();
	}
}
