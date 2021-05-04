package ca.dumezthomas.toptalproject.server.data;

import java.io.Serializable;

public class Passwords implements Serializable
{
	private static final long serialVersionUID = 1L;

	private String oldPassword;
	private String newPassword1;
	private String newPassword2;
	
	public String getOldPassword()
	{
		return oldPassword;
	}
	
	public void setOldPassword(String oldPassword)
	{
		this.oldPassword = oldPassword;
	}
	
	public String getNewPassword1()
	{
		return newPassword1;
	}
	
	public void setNewPassword1(String newPassword1)
	{
		this.newPassword1 = newPassword1;
	}
	
	public String getNewPassword2()
	{
		return newPassword2;
	}
	
	public void setNewPassword2(String newPassword2)
	{
		this.newPassword2 = newPassword2;
	}
}
