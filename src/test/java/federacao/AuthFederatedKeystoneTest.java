package federacao;

import keystone.FederatedKeystoneTest;

import org.junit.Before;

public abstract class AuthFederatedKeystoneTest extends FederatedKeystoneTest {

	static String CANA_ENDPOINT = "http://cana.ect.ufrn.br:5000/v2.0";
	
	static String IDP_REALM = "idp.ect.ufrn.br";
	static String USERNAME1 = "student";
	static String PASSWORD1 = "student";
	

	@Before
	public void setUp() throws Exception {
		keystoneClient = new AuthFederatedKeystone(CANA_ENDPOINT);
		this.KEYSTONE_ENDPOINT = CANA_ENDPOINT;
		this.REALM = IDP_REALM;
		this.IDP_ENDPOINT = null;
		
		keystoneClient.setUsername(USERNAME1);
		keystoneClient.setPassword(PASSWORD1);
	}

}
