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
        try{
            Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
            Entity user = txn.get(userKey);
            if(user != null) {
                txn.rollback();
                return Response.status(Status.CONFLICT).entity("User already exists.").build();
            }else{
                user = Entity.newBuilder(userKey).set("email", data.email)
                        .set("name", data.name).set("phone", data.phone)
                        .set("password", DigestUtils.sha512Hex(data.password))
                        .set("perfil",data.perfil).build();
                txn.put(user);
                txn.commit();
                LOG.info("Created user: " + data.username);
                return Response.ok().build();
            }
        }catch(DatastoreException e){
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();
        }finally{
            if(txn.isActive()){
                txn.rollback();
            }
        }
    }


}
