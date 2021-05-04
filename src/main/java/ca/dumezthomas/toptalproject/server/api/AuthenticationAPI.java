package ca.dumezthomas.toptalproject.server.api;

import javax.ejb.EJB;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import ca.dumezthomas.toptalproject.server.authentication.Authentication;
import ca.dumezthomas.toptalproject.server.dao.interfaces.DAOLocal;
import ca.dumezthomas.toptalproject.server.data.Credentials;
import ca.dumezthomas.toptalproject.server.entity.User;

@Path("authentication")
public class AuthenticationAPI
{
	@EJB(beanName = "UserEJB")
	private DAOLocal<User> userDAO;

	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response authenticate(Credentials credentials)
	{
		try
		{
			User user = userDAO.readByStringId(credentials.getUsername());
			if(user == null)
				throw new Exception("Invalid user");
			
			if(!Authentication.isSamePassword(credentials.getPassword(), user.getPassword()))
				throw new Exception("Invalid password");
			
			String token = Authentication.createToken(user.getUsername(), user.getRole());

			return Response.ok().entity(token).build();
		}
		catch (Exception e)
		{
			return Response.status(Status.UNAUTHORIZED).entity("Authentication failed: " + e.getMessage()).build();
		}
	}
	
	@POST
	@Path("extend")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response extend(String token)
	{
		try
		{
			String newToken = Authentication.refreshToken(token);

			return Response.ok().entity(newToken).build();
		}
		catch (Exception e)
		{
			return Response.status(Status.UNAUTHORIZED).entity("Refresh token failed: " + e.getMessage()).build();
		}
	}
	
	
}