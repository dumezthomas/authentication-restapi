package ca.dumezthomas.toptalproject.server.authentication;

import java.io.IOException;
import java.lang.reflect.AnnotatedElement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.ext.Provider;

@Secured
@Provider
@Priority(Priorities.AUTHORIZATION)
public class Authorization implements ContainerRequestFilter
{
	@Context
	private ResourceInfo resourceInfo;

	@Context
	SecurityContext securityContext;

	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException
	{
		try
		{
			List<String> methodRoles = getRoles(resourceInfo.getResourceMethod());
			if (!methodRoles.isEmpty())
			{
				checkRoles(methodRoles);
				return;
			}

			List<String> classRoles = getRoles(resourceInfo.getResourceClass());
			if (!classRoles.isEmpty())
				checkRoles(classRoles);
		}
		catch (Exception e)
		{
			requestContext
					.abortWith(Response.status(Status.FORBIDDEN).entity("Not authorized : " + e.getMessage()).build());
		}
	}

	private List<String> getRoles(AnnotatedElement annotatedElement) throws Exception
	{
		if (annotatedElement == null)
			return new ArrayList<String>();

		Secured secured = annotatedElement.getAnnotation(Secured.class);
		if (secured == null)
			return new ArrayList<String>();

		return Arrays.asList(secured.value());
	}

	private void checkRoles(List<String> allowedRoles) throws Exception
	{
		if (allowedRoles.stream().noneMatch(s -> securityContext.isUserInRole(s)))
			throw new Exception("User not in role");
	}
}