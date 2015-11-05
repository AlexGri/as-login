package org.comsoft.jboss.login;

import org.apache.commons.codec.digest.DigestUtils;
import org.jboss.security.ErrorCodes;
import org.jboss.security.SimpleGroup;
import org.jboss.security.auth.spi.BaseCertLoginModule;
import org.jboss.security.auth.spi.DatabaseCertLoginModule;
import org.jboss.security.auth.spi.DatabaseServerLoginModule;
import org.jboss.security.plugins.TransactionManagerLocator;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.sql.DataSource;
import javax.transaction.SystemException;
import javax.transaction.Transaction;
import javax.transaction.TransactionManager;
import java.security.Principal;
import java.security.acl.Group;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

/**
 * Кастомный jboss логин модуль.
 * Использует фингерпринт (sha1 хэш) предоставленного пользователем сертификата как параметр
 * для поиска имени Principal` a. затем использует это имя как параметр для запроса поска ролей.
 * Это немного модифицированный копипаст {@link DatabaseCertLoginModule} и {@link DatabaseServerLoginModule}.
 */
public class DatabaseCertHashLoginModule extends BaseCertLoginModule {
	private static final String PRINCIPALS_QUERY = "principalsQuery";
	private static final String DS_JNDI_NAME = "dsJndiName";
	private static final String ROLES_QUERY = "rolesQuery";
	private static final String SUSPEND_RESUME = "suspendResume";
	protected String TX_MGR_JNDI_NAME = "java:/TransactionManager";

	private static final String[] ALL_VALID_OPTIONS =
			{
					PRINCIPALS_QUERY, DS_JNDI_NAME, ROLES_QUERY, SUSPEND_RESUME
			};

	private String principalsQuery;
	/**
	 * The JNDI name of the DataSource to use
	 */
	private String dsJndiName;
	/**
	 * The sql query to obtain the user roles
	 */
	private String rolesQuery = "select Role, RoleGroup from Roles where PrincipalID=?";
	/**
	 * Whether to suspend resume transactions during database operations
	 */
	protected boolean suspendResume = true;
	private String fingerprint;

	protected TransactionManager tm = null;
	private Principal idPrincipal = null;

	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
		addValidOptions(ALL_VALID_OPTIONS);
		super.initialize(subject, callbackHandler, sharedState, options);
		Object tmp = options.get(PRINCIPALS_QUERY);
		if (tmp != null)
			principalsQuery = tmp.toString();
		dsJndiName = (String) options.get(DS_JNDI_NAME);
		if (dsJndiName == null)
			dsJndiName = "java:/DefaultDS";

		tmp = options.get(ROLES_QUERY);
		if (tmp != null)
			rolesQuery = tmp.toString();

		tmp = options.get(SUSPEND_RESUME);
		if (tmp != null)
			suspendResume = Boolean.valueOf(tmp.toString()).booleanValue();
		if (trace) {
			log.trace("DatabaseServerLoginModule, dsJndiName=" + dsJndiName);
			log.trace("rolesQuery=" + rolesQuery);
			log.trace("suspendResume=" + suspendResume);
			log.trace("principalsQuery=" + principalsQuery);
		}

		try {
			if (this.suspendResume)
				tm = this.getTransactionManager();
		} catch (NamingException e) {
			throw new RuntimeException(ErrorCodes.PROCESSING_FAILED + "Unable to get Transaction Manager", e);
		}

	}

	@Override
	protected Principal getIdentity() {
		return idPrincipal;
	}

	@Override
	public boolean login() throws LoginException {
		if (trace)
			log.trace("enter: login()");
		boolean wasSuccessful = super.login();
		if (wasSuccessful) {
			String principal = principalName();
			try {
				idPrincipal = createIdentity(principal);
			} catch (Exception e) {
				e.printStackTrace();
			}
			wasSuccessful = idPrincipal != null;

		}
		if (trace)
			log.trace("exit: login()");
		return wasSuccessful;
	}

	protected String getFingerprint() {
		if (fingerprint != null) return fingerprint;
		X509Certificate certificate = (X509Certificate) getCredentials();
		try {
			fingerprint = DigestUtils.shaHex(certificate.getEncoded());
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		}
		return fingerprint;
	}

	protected String principalName() throws LoginException {
		boolean trace = log.isTraceEnabled();
		String fp = getFingerprint();
		String name = null;
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;

		Transaction tx = getTransaction(suspendResume);

		try {
			InitialContext ctx = new InitialContext();
			DataSource ds = (DataSource) ctx.lookup(dsJndiName);
			conn = ds.getConnection();
			// Get the password
			if (trace)
				log.trace("Excuting query: " + principalsQuery + ", with fingerprint: " + fp);
			ps = conn.prepareStatement(principalsQuery);
			ps.setString(1, fp);
			rs = ps.executeQuery();
			if (rs.next() == false) {
				if (trace)
					log.trace("Query returned no matches from db");
				throw new FailedLoginException(ErrorCodes.PROCESSING_FAILED + "No matching username found in Principals");
			}

			name = rs.getString(1);
			if (trace)
				log.trace("Obtained user password");
		} catch (NamingException ex) {
			LoginException le = new LoginException(ErrorCodes.PROCESSING_FAILED + "Error looking up DataSource from: " + dsJndiName);
			le.initCause(ex);
			throw le;
		} catch (SQLException ex) {
			LoginException le = new LoginException(ErrorCodes.PROCESSING_FAILED + "Query failed");
			le.initCause(ex);
			throw le;
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (SQLException e) {
				}
			}
			if (ps != null) {
				try {
					ps.close();
				} catch (SQLException e) {
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (SQLException ex) {
				}
			}
			if (suspendResume) {
				//TransactionDemarcationSupport.resumeAnyTransaction(tx);
				try {
					tm.resume(tx);
				} catch (Exception e) {
					throw new RuntimeException(e);
				}
				if (log.isTraceEnabled())
					log.trace("resumeAnyTransaction");
			}
		}
		return name;
	}

	@Override
	protected Group[] getRoleSets() throws LoginException {
		String hash = getFingerprint();
		Group[] roleSets = roleSets(hash, dsJndiName, rolesQuery, suspendResume);
		return roleSets;
	}

	public Group[] roleSets(String username, String dsJndiName,
														 String rolesQuery, boolean suspendResume)
			throws LoginException {
		boolean trace = log.isTraceEnabled();
		Connection conn = null;
		HashMap<String, Group> setsMap = new HashMap<String, Group>();
		PreparedStatement ps = null;
		ResultSet rs = null;

		Transaction tx = getTransaction(suspendResume);

		try {
			InitialContext ctx = new InitialContext();
			DataSource ds = (DataSource) ctx.lookup(dsJndiName);
			conn = ds.getConnection();
			// Get the user role names
			if (trace)
				log.trace("Excuting query: " + rolesQuery + ", with username: " + username);
			ps = conn.prepareStatement(rolesQuery);
			try {
				ps.setString(1, username);
			} catch (ArrayIndexOutOfBoundsException ignore) {
				// The query may not have any parameters so just try it
			}
			rs = ps.executeQuery();
			if (rs.next() == false) {
				if (trace)
					log.trace("No roles found");
				if (getUnauthenticatedIdentity() == null)
					throw new FailedLoginException(ErrorCodes.PROCESSING_FAILED + "No matching username found in Roles");
					 /* We are running with an unauthenticatedIdentity so create an
              empty Roles set and return.
           */
				Group[] roleSets = {new SimpleGroup("Roles")};
				return roleSets;
			}

			do {
				String name = rs.getString(1);
				String groupName = rs.getString(2);
				if (groupName == null || groupName.length() == 0)
					groupName = "Roles";
				Group group = (Group) setsMap.get(groupName);
				if (group == null) {
					group = new SimpleGroup(groupName);
					setsMap.put(groupName, group);
				}

				try {
					Principal p = createIdentity(name);
					if (trace)
						log.trace("Assign user to role " + name);
					group.addMember(p);
				} catch (Exception e) {
					log.debug("Failed to create principal: " + name, e);
				}
			} while (rs.next());
		} catch (NamingException ex) {
			LoginException le = new LoginException(ErrorCodes.PROCESSING_FAILED + "Error looking up DataSource from: " + dsJndiName);
			le.initCause(ex);
			throw le;
		} catch (SQLException ex) {
			LoginException le = new LoginException(ErrorCodes.PROCESSING_FAILED + "Query failed");
			le.initCause(ex);
			throw le;
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (SQLException e) {
				}
			}
			if (ps != null) {
				try {
					ps.close();
				} catch (SQLException e) {
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception ex) {
				}
			}
			if (suspendResume) {
				//TransactionDemarcationSupport.resumeAnyTransaction(tx);
				try {
					tm.resume(tx);
				} catch (Exception e) {
					throw new RuntimeException(e);
				}
				if (trace)
					log.trace("resumeAnyTransaction");
			}
		}

		Group[] roleSets = new Group[setsMap.size()];
		setsMap.values().toArray(roleSets);
		return roleSets;
	}

	private Transaction getTransaction(boolean suspendResume) {
		Transaction tx = null;
		if (suspendResume) {
			//tx = TransactionDemarcationSupport.suspendAnyTransaction();
			try {
				if (tm == null)
					throw new IllegalStateException(ErrorCodes.NULL_VALUE + "Transaction Manager is null");
				tx = tm.suspend();
			} catch (SystemException e) {
				throw new RuntimeException(e);
			}
			if (log.isTraceEnabled())
				log.trace("suspendAnyTransaction");
		}
		return tx;
	}

	protected TransactionManager getTransactionManager() throws NamingException {
		TransactionManagerLocator tml = new TransactionManagerLocator();
		return tml.getTM(this.TX_MGR_JNDI_NAME);
	}
}
