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
import jakarta.ws.rs.PathParam;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import pt.unl.fct.di.apdc.firstwebapp.util.LoginInfo;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

@Path("/utility")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class UtilityResource {

    private static final Logger LOG = Logger.getLogger(UtilityResource.class.getName());
    private final Gson g = new Gson();
    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    public UtilityResource() {}

    @Path("/changeRole/{username}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response changeRole(@PathParam("username") String username, String token, String role) {
        LOG.fine("Changing role: " + username);

        Transaction txn = datastore.newTransaction();
        try {
            Key key = datastore.newKeyFactory().setKind("Token").newKey(token);
            Entity tokenEntity = datastore.get(key);

            if (tokenEntity == null || !isTokenValid(tokenEntity.getString("validTo"))) {
                if (tokenEntity != null) {
                    datastore.delete(key);
                }
                txn.rollback();
                return Response.status(Status.UNAUTHORIZED)
                        .entity("Token inválido ou expirado. Sessão de login necessária.")
                        .build();
            }

            Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
            Entity userEntity = datastore.get(userKey);

            if (userEntity == null) {
                datastore.delete(key);
                txn.rollback();
                return Response.status(Status.NOT_FOUND).entity("User not found").build();
            }

            Key requestingUserKey = datastore.newKeyFactory().setKind("User").newKey(tokenEntity.getString("user"));
            Entity requestingUserEntity = datastore.get(requestingUserKey);
            String userRole = requestingUserEntity.getString("role");

            if (!isRoleValid(role)) {
                txn.rollback();
                return Response.status(Status.BAD_REQUEST).entity("Not a valid role").build();
            }

            switch (userRole) {
                case "ADMIN":
                    userEntity = Entity.newBuilder(userEntity)
                            .set("role", role).build();
                    txn.put(userEntity);
                    txn.commit();
                    return Response.status(Status.ACCEPTED).entity("Role changed to " + role).build();
                case "BACKOFFICE":
                    if (role.equals("ENDUSER") || role.equals("PARTNER")) {
                        userEntity = Entity.newBuilder(userEntity)
                                .set("role", role).build();
                        txn.put(userEntity);
                        txn.commit();
                        return Response.status(Status.ACCEPTED).entity("Role changed to " + role).build();
                    } else {
                        txn.rollback();
                        return Response.status(Status.BAD_REQUEST).entity("Not a valid role").build();
                    }
                default:
                    txn.rollback();
                    return Response.status(Status.BAD_REQUEST).entity("You cannot change roles").build();
            }
        } catch (Exception e) {
            txn.rollback();
            return Response.status(Status.INTERNAL_SERVER_ERROR)
                    .entity("An error occurred: " + e.getMessage()).build();
        }
    }

    private boolean isRoleValid(String role) {
        return role.equals("ADMIN") || role.equals("ENDUSER") || role.equals("PARTNER") || role.equals("BACKOFFICE");
    }

    private boolean isTokenValid(String validToString) {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("MMM dd, yyyy, hh:mm:ss a");
            Date validToDate = sdf.parse(validToString);
            Date currentDate = new Date();
            return validToDate.after(currentDate);
        } catch (ParseException e) {
            return false;
        }
    }
}
