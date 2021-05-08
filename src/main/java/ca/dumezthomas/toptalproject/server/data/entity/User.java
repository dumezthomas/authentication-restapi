package ca.dumezthomas.toptalproject.server.data.entity;

import java.io.Serializable;
import java.util.Set;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;

@Entity
@Table(name = "user")
public class User implements Serializable, Comparable<User>
{
	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "id")
	private Long id;
	
	@NotNull
	@Column(name = "username")
	private String username;

	@NotNull
	@Column(name = "password")
	private String password;
	
	@OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
	@JoinColumn(name = "user_id")
	private Set<Role> role;

	@NotNull
	@Column(name = "first_name")
	private String firstName;

	@NotNull
	@Column(name = "last_name")
	private String lastName;
	
	public User()
	{
	}
	
	public User(String username, String password, Set<Role> role, String firstName, String lastName)
	{
		setUsername(username);
		setPassword(password);
		setRole(role);
		setFirstName(firstName);
		setLastName(lastName);
	}

	@Override
	public int compareTo(User user)
	{
		return username.compareTo(user.username);
	}
	
	@Override
	public String toString()
	{
		if(role.stream().anyMatch(r -> r.getRole().equals(Role.ADMIN)))
			return username + " (" + firstName + " " + lastName + ") -- ADMIN";
		else
			return username + " (" + firstName + " " + lastName + ")";
	}

	public Long getId()
	{
		return id;
	}

	public void setId(Long id)
	{
		this.id = id;
	}

	public String getUsername()
	{
		return username;
	}

	public void setUsername(String username)
	{
		this.username = username;
	}

	public String getPassword()
	{
		return password;
	}

	public void setPassword(String password)
	{
		this.password = password;
	}

	public Set<Role> getRole()
	{
		return role;
	}

	public void setRole(Set<Role> role)
	{
		this.role = role;
	}

	public String getFirstName()
	{
		return firstName;
	}

	public void setFirstName(String firstName)
	{
		this.firstName = firstName;
	}

	public String getLastName()
	{
		return lastName;
	}

	public void setLastName(String lastName)
	{
		this.lastName = lastName;
	}
}
