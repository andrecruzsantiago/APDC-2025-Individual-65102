package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.text.ParseException;
import java.text.SimpleDateFormat;

import java.util.Date;
import java.util.logging.Logger;


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

import com.google.gson.Gson;

@Path("/utils")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class utilsResource {

    private static final Logger LOG = Logger.getLogger(utilsResource.class.getName());
    private final Gson g = new Gson();
    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    public utilsResource() {}

    @POST
    @Path("/role")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changeRole(String username, String token, String role) throws ParseException {

        if (!validRole(role)) {
            return Response.status(Status.BAD_REQUEST).build();
        }

        Transaction tx = datastore.newTransaction();
        try {
            Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(token);
            Entity userToken = tx.get(tokenKey);
            if (!isTokenValid(userToken)) {
                tx.rollback();
                return Response.status(Status.NOT_FOUND).entity("Invalid Token").build();
            }

            Key usernameKey = datastore.newKeyFactory().setKind("User").newKey(username);
            Entity userEntity = tx.get(usernameKey);
            if (userEntity == null) {
                tx.rollback();
                return Response.status(Status.NOT_FOUND).build();
            }
            return Response.ok().build();
        } catch (DatastoreException e) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();
        } finally {
            if (tx.isActive()) {
                tx.rollback();
            }
        }
    }

    private boolean validRole(String role) {
        return role != null && (role.equals("ADMIN") || role.equals("ENDUSER") || role.equals("BACKOFFICE") || role.equals("PARTNER"));
    }


    private boolean isTokenValid(Entity userToken) throws ParseException {
        if (userToken == null) {
            return false;
        }
        SimpleDateFormat sdf = new SimpleDateFormat("MMM d, yyyy, h:mm:ss a");
        Date validTo = sdf.parse(userToken.getString("validTo"));
        Date now = new Date();
        return now.before(validTo);

    }
}
