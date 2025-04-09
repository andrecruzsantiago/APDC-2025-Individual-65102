package pt.unl.fct.di.apdc.firstwebapp.resources;

import com.google.cloud.datastore.*;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import com.google.gson.Gson;
import pt.unl.fct.di.apdc.firstwebapp.util.Info;

import java.util.logging.Logger;

@Path("/utils")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class utilsResource {

    private static final Logger LOG = Logger.getLogger(utilsResource.class.getName());
    private final Gson g = new Gson();
    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    public utilsResource() {}

    private Response verifyTokenAndGetEntities(String username, String tokenId, Info data) {
        Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity userEntity = datastore.get(userKey);

        Key targetKey = datastore.newKeyFactory().setKind("User").newKey(data.target);
        Entity targetEntity = datastore.get(targetKey);

        if (userEntity == null || targetEntity == null) {
            return Response.status(Status.NOT_FOUND).build();
        }

        Query<Entity> query = Query.newEntityQueryBuilder()
                .setKind("Token")
                .setFilter(StructuredQuery.PropertyFilter.eq("tokenId", tokenId))
                .build();

        var existingUser = datastore.run(query);

        if (!existingUser.hasNext()) {
            return Response.status(Status.NOT_FOUND).entity("Token doesn't exist").build();
        }

        Entity tokenEntity = existingUser.next();
        if (tokenEntity.getLong("validTo") < System.currentTimeMillis()) {
            datastore.delete(tokenEntity.getKey());
            return Response.status(Status.BAD_REQUEST).entity("You have to login again").build();
        }

        if (!tokenEntity.getKey().getName().equals(username)) {
            return Response.status(Status.FORBIDDEN).entity("The token is not yours.").build();
        }

        return null;
    }

    @POST
    @Path("/role/{username}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changeRole(@PathParam("username") String username, Info data) {

        Response tokenCheckResponse = verifyTokenAndGetEntities(username, data.tokenId, data);
        if (tokenCheckResponse != null) {
            return tokenCheckResponse;
        }

        Key targetKey = datastore.newKeyFactory().setKind("User").newKey(data.target);
        Entity targetEntity = datastore.get(targetKey);
        Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity userEntity = datastore.get(userKey);

        String role = data.param;

        if (!role.equals("ADMIN") && !role.equals("ENDUSER") && !role.equals("BACKOFFICE") && !role.equals("PARTNER")) {
            return Response.status(Status.BAD_REQUEST).entity("Wrong role to assign").build();
        }

        switch (userEntity.getString("role")) {
            case "ADMIN":
                targetEntity = Entity.newBuilder(targetEntity).set("role", role).build();
                break;
            case "BACKOFFICE":
                if ((role.equals("PARTNER") || role.equals("ENDUSER")) &&
                    (targetEntity.getString("role").equals("PARTNER") || targetEntity.getString("role").equals("ENDUSER"))) {
                    targetEntity = Entity.newBuilder(targetEntity).set("role", role).build();
                } else {
                    return Response.status(Status.BAD_REQUEST).entity("Wrong role to assign").build();
                }
                break;
        }

        Transaction txn = datastore.newTransaction();
        try {
            txn.update(targetEntity);
            txn.commit();
            return Response.ok().build();
        } catch (DatastoreException e) {
            txn.rollback();
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }

    @POST
    @Path("/status/{username}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changeStatus(@PathParam("username") String username, Info data) {

        Response tokenCheckResponse = verifyTokenAndGetEntities(username, data.tokenId, data);
        if (tokenCheckResponse != null) {
            return tokenCheckResponse;
        }

        Key targetKey = datastore.newKeyFactory().setKind("User").newKey(data.target);
        Entity targetEntity = datastore.get(targetKey);
        Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity userEntity = datastore.get(userKey);

        String status = data.param;

        if (!status.equals("DESATIVADA") && !status.equals("ATIVADA") && !status.equals("SUSPENSA")) {
            return Response.status(Status.BAD_REQUEST).entity("Wrong role to assign").build();
        }

        switch (userEntity.getString("role")) {
            case "ADMIN":
                targetEntity = Entity.newBuilder(targetEntity).set("status", status).build();
                break;
            case "BACKOFFICE":
                if ((status.equals("DESATIVADA") || status.equals("ATIVADA")) &&
                        (targetEntity.getString("status").equals("ATIVADA") || targetEntity.getString("status").equals("DESATIVADA"))) {
                    targetEntity = Entity.newBuilder(targetEntity).set("status", status).build();
                } else {
                    return Response.status(Status.BAD_REQUEST).entity("Wrong status to assign").build();
                }
                break;
        }

        Transaction txn = datastore.newTransaction();
        try {
            txn.update(targetEntity);
            txn.commit();
            return Response.ok().build();
        } catch (DatastoreException e) {
            txn.rollback();
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }
}
