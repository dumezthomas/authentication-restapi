package ca.dumezthomas.toptalproject.server.entity;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Column;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "role")
public class Role implements Serializable
{
	private static final long serialVersionUID = 1L;
	public static final String USER = "USER";
	public static final String ADMIN = "ADMIN";

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "id")
	private Long id;
	
	@Column(name = "user_id")
	private Long userId;

	@Column(name = "role")
	private String role;
	
	public Role()
	{
	}
	
	public Role(String role)
	{
		setRole(role);
	}
	
	@Override
	public String toString()
	{
		return role + " (user: " + userId + ")";
	}

	public Long getId()
	{
		return id;
	}

	public void setId(Long id)
	{
		this.id = id;
	}

	public Long getUserId()
	{
		return userId;
	}

	public void setUserId(Long userId)
	{
		this.userId = userId;
	}

	public String getRole()
	{
		return role;
	}

	public void setRole(String role)
	{
		if(role.equals(ADMIN))
			this.role = ADMIN;
		else
			this.role = USER;
	}
}
