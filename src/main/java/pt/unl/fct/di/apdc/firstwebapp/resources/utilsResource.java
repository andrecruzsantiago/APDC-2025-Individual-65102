package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.text.ParseException;
import java.text.SimpleDateFormat;

import java.util.Date;
import java.util.logging.Logger;


import com.google.appengine.repackaged.org.apache.commons.codec.digest.DigestUtils;
import com.google.cloud.datastore.*;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

import com.google.gson.Gson;
import pt.unl.fct.di.apdc.firstwebapp.util.Info;

@Path("/utils")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class utilsResource {

    private static final Logger LOG = Logger.getLogger(utilsResource.class.getName());
    private final Gson g = new Gson();
    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    public utilsResource() {}

    @POST
    @Path("/role/{username}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changeRole(@PathParam("username") String username, Info data) {

        Key targetKey = datastore.newKeyFactory().setKind("User").newKey(data.target);
        Entity targetEntity = datastore.get(targetKey);

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity userEntity = datastore.get(userKey);

        if(userEntity == null || targetEntity == null) {
            return Response.status(Status.NOT_FOUND).build();
        }
        Transaction txn = datastore.newTransaction();
        try {
            Query<Entity> query = Query.newEntityQueryBuilder()
                    .setKind("Token")
                    .setFilter(StructuredQuery.PropertyFilter.eq("tokenId", data.tokenId))
                    .build();

            var existingUser = datastore.run(query);

            if(!existingUser.hasNext()) {
                txn.rollback();
                return Response.status(Status.NOT_FOUND).entity("Token doesnt exist").build();

            } else {
                Entity newUserEntity = existingUser.next();
                if(newUserEntity.getLong("validTo") < System.currentTimeMillis()) {
                    datastore.delete(newUserEntity.getKey());
                    return Response.status(Status.BAD_REQUEST).entity("You have to login again").build();
                }
                if(!newUserEntity.getKey().getName().equals(username)) {
                    txn.rollback();
                    return  Response.status(Status.FORBIDDEN).entity("The token is not yours.").build();
                }

                String role = data.param;

                if(!role.equals("ADMIN") && !role.equals("ENDUSER") && !role.equals("BACKOFFICE") && !role.equals("PARTNER")) {
                    return Response.status(Status.BAD_REQUEST).entity("Wrong role to assign").build();
                }

                switch(userEntity.getString("role")){
                    case "ADMIN":
                        targetEntity = Entity.newBuilder(targetEntity).set("role", role).build();
                        break;
                        case "BACKOFFICE":
                            if(role.equals("PARTNER") || role.equals("ENDUSER")) {
                                targetEntity = Entity.newBuilder(targetEntity).set("role", role).build();
                            }else return Response.status(Status.BAD_REQUEST).entity("Wrong role to assign").build();
                        break;

                }
                txn.update(targetEntity);
                txn.commit();
                return Response.ok().build();
            }
        } catch (DatastoreException e) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }

}
