package pt.unl.fct.di.apdc.firstwebapp.resources;
import java.util.logging.Logger;

import com.google.appengine.repackaged.org.apache.commons.codec.digest.DigestUtils;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

import com.google.cloud.datastore.*;
import pt.unl.fct.di.apdc.firstwebapp.util.User;

import com.google.gson.Gson;


@Path("/register")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class CreateUserResource {


    private static final Logger LOG = Logger.getLogger(CreateUserResource.class.getName());
    private final Gson g = new Gson();
    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    public CreateUserResource() {

    }

    @POST
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response register(User data) {
        LOG.fine("Attempting to create: " + data.username);

        if(!data.isValid()) {
            return Response.status(Status.BAD_REQUEST).entity("Wrong input given.").build();
        }

        Transaction txn = datastore.newTransaction();
        try {
            Query<Entity> query = Query.newEntityQueryBuilder()
                    .setKind("User")
                    .setFilter(StructuredQuery.PropertyFilter.eq("email", data.email))
                    .build();

            var existingUser = datastore.run(query);

            if(existingUser.hasNext()) {
                txn.rollback();
                return Response.status(Status.CONFLICT).entity("Email already exists.").build();
            } else {
                Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
                Entity username = txn.get(userKey);

                if (username != null) {
                    txn.rollback();
                    return Response.status(Status.CONFLICT).entity("Username already exists.").build();
                }

                Entity.Builder userBuilder = Entity.newBuilder(userKey)
                        .set("email", data.email)
                        .set("name", data.name)
                        .set("phone", data.phone)
                        .set("password", DigestUtils.sha512Hex(data.password))
                        .set("perfil", data.perfil)
                        .set("status", "DESATIVADA")
                        .set("role", "ENDUSER");

                if (data.cc != null) {
                    userBuilder.set("cc", data.cc);
                }
                if (data.nif != null) {
                    userBuilder.set("nif", data.nif);
                }
                if (data.employee != null) {
                    userBuilder.set("employee", data.employee);
                }
                if (data.function != null) {
                    userBuilder.set("function", data.function);
                }
                if (data.address != null) {
                    userBuilder.set("address", data.address);
                }
                if (data.nifEmp != null) {
                    userBuilder.set("nifEmp", data.nifEmp);
                }
                if (data.photo != null) {
                    userBuilder.set("photo", data.photo);
                }

                Entity user = userBuilder.build();

                txn.put(user);
                txn.commit();
                LOG.info("Created user: " + data.username);
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
