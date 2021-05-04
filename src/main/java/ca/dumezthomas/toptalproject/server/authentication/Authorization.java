package ca.dumezthomas.toptalproject.server.authentication;

import java.io.IOException;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.ext.Provider;

@Secured
@Provider
@Priority(Priorities.AUTHORIZATION)
public class Authorization implements ContainerRequestFilter
{
	@Context
	private ResourceInfo resourceInfo;

	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException
	{
		/*
		Class<?> resourceClass = resourceInfo.getResourceClass();
		List<String> classRoles = extractRoles(resourceClass);

		Method resourceMethod = resourceInfo.getResourceMethod();
		List<String> methodRoles = extractRoles(resourceMethod);

		try
		{
			if (methodRoles.isEmpty())
				checkPermissions(classRoles);
			else
				checkPermissions(methodRoles);
		}
		catch (Exception e)
		{
			requestContext.abortWith(Response.status(Response.Status.FORBIDDEN).build());
		}
		*/
	}
/*
	private List<String> extractRoles(AnnotatedElement annotatedElement)
	{
		if (annotatedElement == null)
			return new ArrayList<String>();
		else
		{
			Secured secured = annotatedElement.getAnnotation(Secured.class);
			if (secured == null)
				return new ArrayList<String>();
			else
			{
				String[] allowedRoles = secured.value();
				return Arrays.asList(allowedRoles);
			}
		}
	}

	private void checkPermissions(List<String> allowedRoles) throws Exception
	{
		// Check if the user contains one of the allowed roles
		// Throw an Exception if the user has not permission to execute the method
	}
	*/
}