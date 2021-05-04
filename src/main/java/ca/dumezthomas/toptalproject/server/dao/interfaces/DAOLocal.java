package ca.dumezthomas.toptalproject.server.dao.interfaces;

import java.util.List;

import javax.ejb.Local;

@Local
public interface DAOLocal<T>
{
	T read(Long id) throws Exception;
	
	T readByStringId(String id) throws Exception;
	
	List<T> readAll() throws Exception;
	
	Long create(T t) throws Exception;

	void updateStrings(Long id, String... args) throws Exception;
	
	void updateString(Long id, String arg) throws Exception;
	
	void delete(Long id) throws Exception;
}
