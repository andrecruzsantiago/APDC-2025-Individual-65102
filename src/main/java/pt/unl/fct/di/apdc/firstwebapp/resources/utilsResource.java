package pt.unl.fct.di.apdc.firstwebapp.resources;

import com.google.appengine.repackaged.org.apache.commons.codec.digest.DigestUtils;
import com.google.cloud.datastore.*;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import com.google.gson.Gson;
import pt.unl.fct.di.apdc.firstwebapp.util.*;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

@Path("/utils")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class utilsResource {

    private static final Logger LOG = Logger.getLogger(utilsResource.class.getName());
    private final Gson g = new Gson();
    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    public utilsResource() {}

    private Response verifyTokenAndGetEntities(String username, String tokenId) {

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
    public Response changeRole(@PathParam("username") String username, TokenParamInfo data) {

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity userEntity = datastore.get(userKey);

        Key targetKey = datastore.newKeyFactory().setKind("User").newKey(data.target);
        Entity targetEntity = datastore.get(targetKey);

        if (userEntity == null || targetEntity == null) {
            return Response.status(Status.NOT_FOUND).build();
        }

        Response tokenCheckResponse = verifyTokenAndGetEntities(username, data.tokenId);
        if (tokenCheckResponse != null) {
            return tokenCheckResponse;
        }

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
            return Response.status(Status.ACCEPTED).entity("Role updated successfully:"+data.target+" ->"+data.param).build();
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
    public Response changeStatus(@PathParam("username") String username, TokenParamInfo data) {

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity userEntity = datastore.get(userKey);

        Key targetKey = datastore.newKeyFactory().setKind("User").newKey(data.target);
        Entity targetEntity = datastore.get(targetKey);

        if (userEntity == null || targetEntity == null) {
            return Response.status(Status.NOT_FOUND).build();
        }

        Response tokenCheckResponse = verifyTokenAndGetEntities(username, data.tokenId);
        if (tokenCheckResponse != null) {
            return tokenCheckResponse;
        }

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
            return Response.status(Status.ACCEPTED).entity("Status updated successfully:"+data.target+" ->"+data.param).build();
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
    @Path("/delete/{username}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response deleteAccount(@PathParam("username") String username, TokenParamInfo data) {

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity userEntity = datastore.get(userKey);

        Key targetKey = datastore.newKeyFactory().setKind("User").newKey(data.target);
        Entity targetEntity = datastore.get(targetKey);

        if (targetEntity == null) {
            Query<Entity> query = Query.newEntityQueryBuilder()
                    .setKind("User")
                    .setFilter(StructuredQuery.PropertyFilter.eq("email", data.target))
                    .build();

            var existingUser = datastore.run(query);
            if (existingUser.hasNext()) {
                targetEntity = existingUser.next();
            }
        }


        if (userEntity == null || targetEntity == null) {
            return Response.status(Status.NOT_FOUND).build();
        }

        Response tokenCheckResponse = verifyTokenAndGetEntities(username, data.tokenId);
        if (tokenCheckResponse != null) {
            return tokenCheckResponse;
        }

        targetKey = targetEntity.getKey();

        switch (userEntity.getString("role")) {
            case "ADMIN":
                datastore.delete(targetEntity.getKey());

                Query<Entity> tokenQuery = Query.newEntityQueryBuilder()
                        .setKind("Token")
                        .setFilter(StructuredQuery.PropertyFilter.
                                hasAncestor(datastore.newKeyFactory().setKind("User").newKey(targetKey.getName())))
                        .build();

                var tokenResult = datastore.run(tokenQuery);
                if (tokenResult.hasNext()) {
                    Entity tokenEntity = tokenResult.next();
                    datastore.delete(tokenEntity.getKey());
                }
                break;

            case "BACKOFFICE":
                String targetRole = targetEntity.getString("role");
                if (!targetRole.equals("ENDUSER") && !targetRole.equals("PARTNER")) {
                    return Response.status(Status.BAD_REQUEST).entity("You cannot delete a user who is not ENDUSER or PARTNER").build();
                }

                datastore.delete(targetEntity.getKey());

                Query<Entity> tokenQuery1 = Query.newEntityQueryBuilder()
                        .setKind("Token")
                        .setFilter(StructuredQuery.PropertyFilter.hasAncestor(datastore.newKeyFactory().setKind("User").newKey(targetKey.getName())))
                        .build();

                var tokenResult1 = datastore.run(tokenQuery1);
                if (tokenResult1.hasNext()) {
                    Entity tokenEntity = tokenResult1.next();
                    datastore.delete(tokenEntity.getKey());
                }

                break;

        }

        return Response.status(Status.ACCEPTED).entity("User deleted:"+data.target).build();
    }

    @POST
    @Path("/listUsers/{username}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response listUsers(@PathParam("username") String username, TokenParamInfo data) {

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity userEntity = datastore.get(userKey);


        if (userEntity == null) {
            return Response.status(Status.NOT_FOUND).build();
        }

        Response tokenCheckResponse = verifyTokenAndGetEntities(username, data.tokenId);
        if (tokenCheckResponse != null) {
            return tokenCheckResponse;
        }

        String requesterRole = userEntity.getString("role");

        StructuredQuery.Builder<Entity> queryBuilder = Query.newEntityQueryBuilder().setKind("User");

        switch (requesterRole) {
            case "ENDUSER":
                queryBuilder.setFilter(StructuredQuery.CompositeFilter.and(
                        StructuredQuery.PropertyFilter.eq("role", "ENDUSER"),
                        StructuredQuery.PropertyFilter.eq("perfil", "publico"),
                        StructuredQuery.PropertyFilter.eq("status", "ATIVADA")
                ));
                break;

            case "BACKOFFICE":
                queryBuilder.setFilter(StructuredQuery.PropertyFilter.eq("role", "ENDUSER"));
                break;
        }

        Query<Entity> query = queryBuilder.build();
        QueryResults<Entity> results = datastore.run(query);

        List<UserToUpdateInfoReceived> userList = new ArrayList<>();

        while (results.hasNext()) {
            Entity u = results.next();
            UserToUpdateInfoReceived userData = new UserToUpdateInfoReceived();

            userData.username = u.getKey().getName();

            if (requesterRole.equals("ENDUSER")) {
                if (u.contains("email")) userData.email = u.getString("email"); else userData.email = "NOT DEFINED";
                if (u.contains("name")) userData.name = u.getString("name"); else userData.name = "NOT DEFINED";
            } else {
                if (u.contains("email")) userData.email = u.getString("email"); else userData.email = "NOT DEFINED";
                if (u.contains("name")) userData.name = u.getString("name"); else userData.name = "NOT DEFINED";
                if (u.contains("role")) userData.role = u.getString("role"); else userData.role = "NOT DEFINED";
                if (u.contains("profile")) userData.perfil = u.getString("profile"); else userData.perfil = "NOT DEFINED";
                if (u.contains("status")) userData.status = u.getString("status"); else userData.status = "NOT DEFINED";
                if (u.contains("phone")) userData.phone = u.getString("phone"); else userData.phone = "NOT DEFINED";
                if (u.contains("address")) userData.address = u.getString("address"); else userData.address = "NOT DEFINED";
                if (u.contains("nif")) userData.nif = u.getString("nif"); else userData.nif = "NOT DEFINED";
                if (u.contains("employer")) userData.employer = u.getString("employer"); else userData.employer = "NOT DEFINED";
                if (u.contains("function")) userData.function = u.getString("function"); else userData.function = "NOT DEFINED";
                if (u.contains("nifEmp")) userData.nifEmp = u.getString("nifEmp"); else userData.nifEmp = "NOT DEFINED";
                if (u.contains("cc")) userData.cc = u.getString("cc"); else userData.cc = "NOT DEFINED";
            }


            userList.add(userData);
        }

        return Response.ok(g.toJson(userList)).build();
    }

    @POST
    @Path("/change/{username}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response update(@PathParam("username") String username, UserToChangeAtributesInfo data) {

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity userEntity = datastore.get(userKey);

        Key targetKey = datastore.newKeyFactory().setKind("User").newKey(data.target);
        Entity targetEntity = datastore.get(targetKey);

        if (userEntity == null || targetEntity == null) {
            return Response.status(Status.NOT_FOUND).build();
        }

        Response tokenCheckResponse = verifyTokenAndGetEntities(username, data.tokenId);
        if (tokenCheckResponse != null) {
            return tokenCheckResponse;
        }

        String requesterRole = userEntity.getString("role");
        String targetStatus = targetEntity.getString("status");

        if (requesterRole.equals("ENDUSER") && !username.equals(data.target)) {
            return Response.status(Status.FORBIDDEN).entity("You can only modify your own account.").build();
        }

        if (requesterRole.equals("BACKOFFICE") && !targetStatus.equals("ATIVADA")) {
            return Response.status(Status.FORBIDDEN).entity("You can only modify activated accounts.").build();
        }

        UserToUpdateInfoReceived userData = new UserToUpdateInfoReceived();

        if (data.email != null) {
            if (!requesterRole.equals("ADMIN") && !username.equals(data.target)) {
                return Response.status(Status.FORBIDDEN).entity("You are not allowed to change email.").build();
            }
            userData.email = data.email;
        }
        if (data.name != null) {
            if (!requesterRole.equals("ADMIN") && !username.equals(data.target)) {
                return Response.status(Status.FORBIDDEN).entity("You are not allowed to change name.").build();
            }
            userData.name = data.name;
        }

        if (data.role != null && (requesterRole.equals("ADMIN") || requesterRole.equals("BACKOFFICE"))) {
            userData.role = data.role;
        }
        if (data.status != null && requesterRole.equals("ADMIN")) {
            userData.status = data.status;
        }

        if (data.perfil != null) userData.perfil = data.perfil;
        if (data.phone != null) userData.phone = data.phone;
        if (data.address != null) userData.address = data.address;
        if (data.nif != null) userData.nif = data.nif;
        if (data.employer != null) userData.employer = data.employer;
        if (data.function != null) userData.function = data.function;
        if (data.nifEmp != null) userData.nifEmp = data.nifEmp;
        if (data.cc != null) userData.cc = data.cc;

        Transaction txn = datastore.newTransaction();
        try {
            if (userData.email != null) targetEntity = Entity.newBuilder(targetEntity).set("email", userData.email).build();
            if (userData.name != null) targetEntity = Entity.newBuilder(targetEntity).set("name", userData.name).build();
            if (userData.role != null) targetEntity = Entity.newBuilder(targetEntity).set("role", userData.role).build();
            if (userData.status != null) targetEntity = Entity.newBuilder(targetEntity).set("status", userData.status).build();
            if (userData.perfil != null) targetEntity = Entity.newBuilder(targetEntity).set("profile", userData.perfil).build();
            if (userData.phone != null) targetEntity = Entity.newBuilder(targetEntity).set("phone", userData.phone).build();
            if (userData.address != null) targetEntity = Entity.newBuilder(targetEntity).set("address", userData.address).build();
            if (userData.nif != null) targetEntity = Entity.newBuilder(targetEntity).set("nif", userData.nif).build();
            if (userData.employer != null) targetEntity = Entity.newBuilder(targetEntity).set("employer", userData.employer).build();
            if (userData.function != null) targetEntity = Entity.newBuilder(targetEntity).set("function", userData.function).build();
            if (userData.nifEmp != null) targetEntity = Entity.newBuilder(targetEntity).set("nifEmp", userData.nifEmp).build();
            if (userData.cc != null) targetEntity = Entity.newBuilder(targetEntity).set("cc", userData.cc).build();

            txn.update(targetEntity);
            txn.commit();

            return Response.status(Status.ACCEPTED).entity("User updated:"+data.target).build();
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
    @Path("/changePass/{username}/")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changePass(@PathParam("username") String username, @QueryParam("currentPass") String currentPassword, PassInfo data) {

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity userEntity = datastore.get(userKey);


        if (userEntity == null ) {
            return Response.status(Status.NOT_FOUND).build();
        }

        Response tokenCheckResponse = verifyTokenAndGetEntities(username, data.tokenId);
        if (tokenCheckResponse != null) {
            return tokenCheckResponse;
        }

        String storedPassword = userEntity.getString("password");
        if (!storedPassword.equals(DigestUtils.sha512Hex(currentPassword))) {
            return Response.status(Status.UNAUTHORIZED).entity("Invalid password.").build();
        }
        if(!data.newPassword.equals(data.passwordRepeat)) {
            return Response.status(Status.CONFLICT).entity("Passwords do not match.").build();
        }
        Transaction txn = datastore.newTransaction();
        try {
            Entity updatedUser = Entity.newBuilder(userEntity)
                    .set("password", DigestUtils.sha512Hex(data.newPassword))
                    .build();

            txn.put(updatedUser);
            txn.commit();
            return Response.ok("Password updated successfully.").build();
        } catch (DatastoreException e) {
            if (txn.isActive())
                txn.rollback();
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Failed to update password.").build();
        }
    }

    @POST
    @Path("/logout/{username}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response logout(@PathParam("username") String username, TokenParamInfo data) {

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity userEntity = datastore.get(userKey);

        if (userEntity == null) {
            return Response.status(Status.NOT_FOUND).entity("Not a available user to logout.").build();
        }

        Query<Entity> query = Query.newEntityQueryBuilder()
                .setKind("Token")
                .setFilter(StructuredQuery.PropertyFilter.eq("tokenId", data.tokenId))
                .build();

        var existingUser = datastore.run(query);

        if (!existingUser.hasNext()) {
            return Response.status(Status.NOT_FOUND).entity("You must be loged in to log out").build();
        }

        Entity existingUserEntity = existingUser.next();

        Transaction txn = datastore.newTransaction();
        try {
            txn.delete(existingUserEntity.getKey());
            txn.commit();
            return Response.status(Status.FOUND).location(URI.create("/logoutPage.html")).build();
        } catch (DatastoreException e) {
            if (txn.isActive()) txn.rollback();
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Logout failed.").build();
        }
    }

    @POST
    @Path("/create/{username}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response createWorkSheet(@PathParam("username") String username, WorkSheet data) {
        Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.partnerUsername);
        Entity userEntity = datastore.get(userKey);
        Key creatorKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity creatorEntity = datastore.get(creatorKey);

        if (userEntity == null || creatorEntity == null) {
            return Response.status(Status.NOT_FOUND).entity("You must choose a valid partner.").build();
        }

        Response tokenCheckResponse = verifyTokenAndGetEntities(username, data.tokenId);
        if (tokenCheckResponse != null) {
            return tokenCheckResponse;
        }

        String role = creatorEntity.getString("role");

        Key sheetKey = datastore.newKeyFactory()
                .addAncestor(PathElement.of("User", data.partnerUsername))
                .setKind("WorkSheet")
                .newKey(data.reference);
        Entity sheetEntity = datastore.get(sheetKey);

        Transaction txn = datastore.newTransaction();
        try {
            if (sheetEntity == null) {
                if (!role.equals("BACKOFFICE")) {
                    txn.rollback();
                    return Response.status(Status.UNAUTHORIZED).entity("Only BACKOFFICE can create worksheets.").build();
                }

                if (data.reference == null || data.description == null || data.type == null || data.awardStatus == null) {
                    txn.rollback();
                    return Response.status(Status.BAD_REQUEST).entity("Missing mandatory fields for worksheet creation.").build();
                }

                if (data.awardStatus.equals("ADJUDICADO")) {
                    if (data.date == 0 || data.startDate == 0 || data.endDate == 0 ||
                            data.awardStatusEntity == null || data.nif == null || data.state == null) {
                        txn.rollback();
                        return Response.status(Status.BAD_REQUEST).entity("Missing adjudication fields.").build();
                    }
                }

                Entity.Builder newSheet = Entity.newBuilder(sheetKey)
                        .set("reference", data.reference)
                        .set("description", data.description)
                        .set("type", data.type)
                        .set("awardStatus", data.awardStatus)
                        .set("partnerUsername", data.partnerUsername)
                        .set("obs", data.obs == null ? "" : data.obs);

                if (data.awardStatus.equals("ADJUDICADO")) {
                    newSheet.set("date", data.date)
                            .set("startDate", data.startDate)
                            .set("endDate", data.endDate)
                            .set("awardStatusEntity", data.awardStatusEntity)
                            .set("nif", data.nif)
                            .set("state", data.state);
                }

                txn.put(newSheet.build());
                txn.commit();
                return Response.ok("Worksheet created successfully.").build();
            } else {
                Entity.Builder updatedSheet = Entity.newBuilder(sheetEntity);
                String awardStatus = sheetEntity.getString("awardStatus");
                String assignedPartner = sheetEntity.getString("partnerUsername");

                if (role.equals("BACKOFFICE")) {
                    updatedSheet.set("description", data.description)
                            .set("type", data.type)
                            .set("awardStatus", data.awardStatus)
                            .set("obs", data.obs == null ? "" : data.obs);

                    if (data.awardStatus.equals("ADJUDICADO")) {
                        if (data.date == 0 || data.startDate == 0 || data.endDate == 0 ||
                                data.awardStatusEntity == null || data.nif == null || data.state == null) {
                            txn.rollback();
                            return Response.status(Status.BAD_REQUEST).entity("Missing adjudication fields.").build();
                        }

                        updatedSheet.set("date", data.date)
                                .set("startDate", data.startDate)
                                .set("endDate", data.endDate)
                                .set("awardStatusEntity", data.awardStatusEntity)
                                .set("nif", data.nif)
                                .set("state", data.state);
                    }

                } else if (role.equals("PARTNER")) {
                    if (!assignedPartner.equals(data.partnerUsername)) {
                        txn.rollback();
                        return Response.status(Status.UNAUTHORIZED).entity("You are not allowed to modify this worksheet.").build();
                    }

                    if (!awardStatus.equals("ADJUDICADO")) {
                        txn.rollback();
                        return Response.status(Status.UNAUTHORIZED).entity("You cannot modify a non-awarded worksheet.").build();
                    }

                    updatedSheet.set("state", data.state)
                            .set("obs", data.obs == null ? "" : data.obs);
                } else {
                    txn.rollback();
                    return Response.status(Status.UNAUTHORIZED).entity("Invalid role.").build();
                }

                txn.put(updatedSheet.build());
                txn.commit();
                return Response.ok("Worksheet updated successfully.").build();
            }
        } catch (DatastoreException e) {
            if (txn.isActive()) txn.rollback();
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Operation failed.").build();
        }
    }

}
