package ca.dumezthomas.toptalproject.server.data;

import java.io.Serializable;

public class Passwords implements Serializable
{
	private static final long serialVersionUID = 1L;

	private String oldPassword;
	private String newPassword;
	
	public String getOldPassword()
	{
		return oldPassword;
	}
	
	public void setOldPassword(String oldPassword)
	{
		this.oldPassword = oldPassword;
	}
	
	public String getNewPassword()
	{
		return newPassword;
	}
	
	public void setNewPassword(String newPassword1)
	{
		this.newPassword = newPassword1;
	}
}
