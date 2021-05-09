package ca.dumezthomas.toptalproject.server.api;

import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.ejb.EJB;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.PATCH;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.Response.Status;

import com.google.gson.Gson;

import ca.dumezthomas.toptalproject.server.authentication.Authentication;
import ca.dumezthomas.toptalproject.server.authentication.Secured;
import ca.dumezthomas.toptalproject.server.dao.interfaces.DAOLocal;
import ca.dumezthomas.toptalproject.server.data.Passwords;
import ca.dumezthomas.toptalproject.server.data.UserIdentity;
import ca.dumezthomas.toptalproject.server.data.entity.Role;
import ca.dumezthomas.toptalproject.server.data.entity.User;

@Secured(Role.ADMIN)
@Path("users")
public class UserAPI
{
	@EJB(beanName = "UserEJB")
	private DAOLocal<User> userDAO;

	@Context
	SecurityContext securityContext;

	@GET
	@Secured({ Role.USER, Role.ADMIN })
	@Produces(MediaType.APPLICATION_JSON)
	public Response getAll(@QueryParam("username") String username)
	{
		if (username != null)
			return getUserByUsername(username);
		else
			return getUsers();
	}

	@GET
	@Secured({ Role.USER, Role.ADMIN })
	@Path("{id}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response get(@PathParam("id") Long id)
	{
		try
		{
			if (securityContext.isUserInRole(Role.USER))
			{
				Principal principal = securityContext.getUserPrincipal();
				if (Long.valueOf(principal.getName()) != id)
					return Response.status(Status.FORBIDDEN).entity("Not authorized").build();
			}

			User user = userDAO.read(id);
			user.setPassword("******");

			String jsonString = new Gson().toJson(user);
			return Response.ok().entity(jsonString).build();
		}
		catch (Exception e)
		{
			return Response.serverError().entity("Read user failed: " + e.getMessage()).build();
		}
	}

	@POST
	@Secured({ Role.USER, Role.ADMIN })
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response add(User user)
	{
		try
		{
			String hash = Authentication.hashPassword(user.getPassword());
			user.setPassword(hash);

			Set<Role> role = new HashSet<>();
			role.add(new Role(Role.USER));
			user.setRole(role);

			Long id = userDAO.create(user);
			String jsonString = new Gson().toJson(id);
			return Response.status(Status.CREATED).entity(jsonString).build();
		}
		catch (Exception e)
		{
			return Response.serverError().entity("Create user failed: " + e.getMessage()).build();
		}
	}

	@PATCH
	@Secured({ Role.USER, Role.ADMIN })
	@Path("{id}")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response update(@PathParam("id") Long id, UserIdentity userIdentity)
	{
		try
		{
			if (securityContext.isUserInRole(Role.USER))
			{
				Principal principal = securityContext.getUserPrincipal();
				if (Long.valueOf(principal.getName()) != id)
					return Response.status(Status.FORBIDDEN).entity("Not authorized").build();
			}

			userDAO.updateStrings(id, userIdentity.getFirstName(), userIdentity.getLastName());
			return Response.ok().entity("{}").build();
		}
		catch (Exception e)
		{
			return Response.serverError().entity("Update user failed: " + e.getMessage()).build();
		}
	}

	@PATCH
	@Secured({ Role.USER, Role.ADMIN })
	@Path("{id}/password")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response updatePassword(@PathParam("id") Long id, Passwords passwords)
	{
		try
		{
			if (securityContext.isUserInRole(Role.USER))
			{
				Principal principal = securityContext.getUserPrincipal();
				if (Long.valueOf(principal.getName()) != id)
					return Response.status(Status.FORBIDDEN).entity("Not authorized").build();
			}

			if (!passwords.getNewPassword1().equals(passwords.getNewPassword2()))
				throw new Exception("Different passwords");

			User user = userDAO.read(id);

			if (!Authentication.isSamePassword(passwords.getOldPassword(), user.getPassword()))
				throw new Exception("Invalid password");

			String hash = Authentication.hashPassword(passwords.getNewPassword1());
			userDAO.updateString(id, hash);

			return Response.ok().entity("{}").build();
		}
		catch (Exception e)
		{
			return Response.serverError().entity("Update password failed: " + e.getMessage()).build();
		}
	}

	@DELETE
	@Secured(Role.ADMIN)
	@Path("{id}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response remove(@PathParam("id") Long id)
	{
		try
		{
			userDAO.delete(id);
			return Response.ok().entity("{}").build();
		}
		catch (Exception e)
		{
			return Response.serverError().entity("Delete user failed: " + e.getMessage()).build();
		}
	}
	
	private Response getUsers()
	{
		try
		{
			if (!securityContext.isUserInRole(Role.ADMIN))
				return Response.status(Status.FORBIDDEN).entity("Not authorized : User not in role").build();

			List<User> userList = userDAO.readAll();
			userList.stream().forEach(u -> u.setPassword("******"));
			Collections.sort(userList);

			String jsonString = new Gson().toJson(userList);
			return Response.ok().entity(jsonString).build();
		}
		catch (Exception e)
		{
			return Response.serverError().entity("Read users failed: " + e.getMessage()).build();
		}
	}

	private Response getUserByUsername(String username)
	{
		try
		{
			User user = userDAO.readByStringId(username);
			user.setPassword("******");

			if (securityContext.isUserInRole(Role.USER))
			{
				Principal principal = securityContext.getUserPrincipal();
				if (Long.valueOf(principal.getName()) != user.getId())
					return Response.status(Status.FORBIDDEN).entity("Not authorized").build();
			}

			String jsonString = new Gson().toJson(user);
			return Response.ok().entity(jsonString).build();
		}
		catch (Exception e)
		{
			return Response.serverError().entity("Read user failed: " + e.getMessage()).build();
		}
	}

}
