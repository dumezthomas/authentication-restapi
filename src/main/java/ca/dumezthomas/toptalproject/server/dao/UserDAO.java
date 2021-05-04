package ca.dumezthomas.toptalproject.server.dao;

import ca.dumezthomas.toptalproject.server.dao.interfaces.DAOLocal;
import ca.dumezthomas.toptalproject.server.entity.User;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

import java.util.List;

import javax.ejb.Stateless;

@Stateless(name = "UserEJB")
public class UserDAO implements DAOLocal<User>
{
	@PersistenceContext(unitName = "EntitiesPU")
	private EntityManager em;

	@Override
	public User read(Long id) throws Exception
	{
		return em.find(User.class, id);
	}

	@Override
	public User readByStringId(String username) throws Exception
	{
		TypedQuery<User> typedQuery = em.createQuery("SELECT u FROM User u WHERE u.username = :username", User.class);
		typedQuery.setParameter("username", username);

		return typedQuery.getSingleResult();
	}

	@Override
	public List<User> readAll() throws Exception
	{
		TypedQuery<User> typedQuery = em.createQuery("SELECT u FROM User u", User.class);

		return typedQuery.getResultList();
	}

	@Override
	public Long create(User user) throws Exception
	{
		User newUser = new User(user.getUsername(), user.getPassword(), user.getRole(), user.getFirstName(),
				user.getLastName());

		em.persist(newUser);
		em.flush();

		return newUser.getId();
	}

	@Override
	public void updateStrings(Long id, String... args) throws Exception
	{
		User temp = read(id);

		temp.setFirstName(args[0]);
		temp.setLastName(args[1]);

		em.merge(temp);
	}
	
	@Override
	public void updateString(Long id, String password) throws Exception
	{
		User temp = read(id);

		temp.setPassword(password);

		em.merge(temp);
	}

	@Override
	public void delete(Long id) throws Exception
	{
		em.remove(read(id));
	}
}
