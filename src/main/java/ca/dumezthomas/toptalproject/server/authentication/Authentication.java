package ca.dumezthomas.toptalproject.server.authentication;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.ext.Provider;

import ca.dumezthomas.toptalproject.server.entity.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.annotation.Priority;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.Priorities;

@Secured
@Provider
@Priority(Priorities.AUTHENTICATION)
public class Authentication implements ContainerRequestFilter
{
	private static final String AUTHENTICATION_SCHEME = "Bearer";

	private static final String KEYSTORE_PWD = "toptalproject";
	private static final String KEYSTORE_FILE = "toptalKeyStore.jks";
	private static final String KEY_ALIAS = "key-jwt-token";
	private static final String KEY_PWD = "toptalproject";

	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException
	{
		try
		{
			String header = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);

			if (header == null)
				throw new Exception("Empty authorization header");

			if (!header.toLowerCase().startsWith(AUTHENTICATION_SCHEME.toLowerCase() + " "))
				throw new Exception("Invalid authorization header");

			String token = header.substring(AUTHENTICATION_SCHEME.length()).trim();

			Claims claim = parseToken(token);

			final SecurityContext securityContext = requestContext.getSecurityContext();

			requestContext.setSecurityContext(new SecurityContext()
			{
				@Override
				public Principal getUserPrincipal()
				{
					return () -> claim.getSubject();
				}

				@Override
				public boolean isUserInRole(String role)
				{
					try
					{
						String[] parts = ((String) claim.get("role")).split(":");
						List<String> listRole = Arrays.asList(parts);

						return listRole.contains(role);
					}
					catch (Exception e)
					{
						return false;
					}
				}

				@Override
				public boolean isSecure()
				{
					return securityContext.isSecure();
				}

				@Override
				public String getAuthenticationScheme()
				{
					return AUTHENTICATION_SCHEME;
				}
			});
		}
		catch (Exception e)
		{
			requestContext.abortWith(
					Response.status(Status.UNAUTHORIZED).entity("Authentication failed: " + e.getMessage()).build());
		}
	}

	public static String hashPassword(String password) throws Exception
	{
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[32];
		random.nextBytes(salt);

		String saltString = new String(Base64.getEncoder().encodeToString(salt));
		String sha256Password = digest_salt_sha256(password, salt);

		return saltString + ":" + sha256Password;
	}

	public static boolean isSamePassword(String password, String storedPassword) throws Exception
	{
		String[] parts = storedPassword.split(":");
		if (parts.length != 2)
			throw new Exception("Invalid password stored");

		byte[] salt = Base64.getDecoder().decode(parts[0].getBytes(StandardCharsets.UTF_8));

		String sha256Password = digest_salt_sha256(password, salt);

		return sha256Password.equals(parts[1]);
	}

	private static String digest_salt_sha256(String password, byte[] salt) throws Exception
	{
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(salt);
		byte[] digest = md.digest(password.getBytes(StandardCharsets.UTF_8));

		return new String(Base64.getEncoder().encodeToString(digest));
	}

	public static String createToken(String username, Set<Role> role) throws Exception
	{
		Key key = new SecretKeySpec(getSecretKey().getEncoded(), SignatureAlgorithm.HS256.getJcaName());

		Instant now = Instant.now();

		StringBuilder listRole = new StringBuilder();
		for (Role temp : role)
			listRole.append(temp.getRole() + ":");

		String token = Jwts.builder().setId(UUID.randomUUID().toString()).setSubject(username)
				.claim("role", listRole.toString()).setIssuedAt(Date.from(now))
				.setExpiration(Date.from(now.plus(5l, ChronoUnit.MINUTES))).signWith(SignatureAlgorithm.HS256, key)
				.compact();

		return token;
	}

	public static String refreshToken(String token) throws Exception
	{
		Claims claim = parseToken(token);
		String username = claim.getSubject();
		String role = (String) claim.get("role");
		Date issuedAt = claim.getIssuedAt();

		Key key = new SecretKeySpec(getSecretKey().getEncoded(), SignatureAlgorithm.HS256.getJcaName());

		Instant now = Instant.now();

		String newToken = Jwts.builder().setId(UUID.randomUUID().toString()).setSubject(username).claim("role", role)
				.setIssuedAt(issuedAt).setExpiration(Date.from(now.plus(5l, ChronoUnit.MINUTES)))
				.signWith(SignatureAlgorithm.HS256, key).compact();

		return newToken;
	}

	private static Claims parseToken(String token) throws Exception
	{
		Key key = new SecretKeySpec(getSecretKey().getEncoded(), SignatureAlgorithm.HS256.getJcaName());

		Claims tokenBody = Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();

		return tokenBody;
	}

	private static Key getSecretKey() throws Exception
	{
		Key key = null;
		KeyStore ks = KeyStore.getInstance("JCEKS");

		try (FileInputStream fis = new FileInputStream(KEYSTORE_FILE))
		{
			ks.load(fis, KEYSTORE_PWD.toCharArray());
			key = ks.getKey(KEY_ALIAS, KEY_PWD.toCharArray());
			if (key == null)
				throw new Exception("Key not found");
		}
		catch (Exception e)
		{
			key = storeSecretKey(generateSecretKey());
		}

		return key;
	}

	private static SecretKey generateSecretKey() throws Exception
	{
		return KeyGenerator.getInstance("AES").generateKey();
	}

	private static Key storeSecretKey(SecretKey secretKey) throws Exception
	{
		KeyStore ks = KeyStore.getInstance("JCEKS");
		ks.load(null, KEYSTORE_PWD.toCharArray());

		KeyStore.SecretKeyEntry secret = new KeyStore.SecretKeyEntry(secretKey);
		KeyStore.ProtectionParameter password = new KeyStore.PasswordProtection(KEY_PWD.toCharArray());
		ks.setEntry(KEY_ALIAS, secret, password);

		try (FileOutputStream fos = new FileOutputStream(KEYSTORE_FILE))
		{
			ks.store(fos, KEYSTORE_PWD.toCharArray());
		}

		return secretKey;
	}
}