package federacao.idpmais;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import keystone.FederatedKeystoneTest;

import org.junit.Before;

public class AuthFederatedKeystoneCanaIDPMaisTest extends FederatedKeystoneTest{

	static String CANA_ENDPOINT = "http://cana.ect.ufrn.br:5000/v2.0";
	static String CANA_ENTITY_ID = "http://cana.ect.ufrn.br:5000";
	
	static String IDPMAIS_REALM = "IdP-stcfed-IFSC";
	static String IDPMAIS_ENDPOINT = "https://idpstcfed.sj.ifsc.edu.br/RNPSecurityTokenService/RNPSTS";
	static String USERNAME1 = "funcionario";
	static String PASSWORD1 = "funcionario123";
	

	static String TENANTID = "312e06f400834de395ce41e7ac28e0cc";
	
	
	@Before
	public void setUp() throws Exception {
		keystoneClient = new AuthFederatedKeystoneCanaIDPMais(CANA_ENDPOINT);
		this.KEYSTONE_ENDPOINT = CANA_ENDPOINT;
		this.REALM = IDPMAIS_REALM;
		this.IDP_ENDPOINT = IDPMAIS_ENDPOINT;
		this.ENTITY_ID = CANA_ENTITY_ID;
		
		keystoneClient.setUsername(USERNAME1);
		keystoneClient.setPassword(PASSWORD1);
	}

	public void processRealm(List<String> realms) {
		boolean found = false;
		selectedRealm = null;
		for (String realm : realms) {
			if (realm.contains(REALM)) {
				found = true;
				selectedRealm = REALM;
			}
			System.out.println("Realm: " + realm);
		}
		assertTrue("Expected realm \"" + REALM + "\" not found.", found);
		assertNotNull(selectedRealm);
		
	}
}
