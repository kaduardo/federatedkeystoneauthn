package federacao.idpmais;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import keystone.FederatedKeystoneTest;

import org.junit.Before;
import org.junit.Test;

public class AuthFederatedKeystoneIDPMaisExpTest extends FederatedKeystoneTest{

	static String CANA_ENDPOINT = "http://cana.ect.ufrn.br:5000/v2.0";
	static String CANA_ENTITY_ID = "http://cana.ect.ufrn.br:5000";
	
	static String IDPMAIS_REALM = "IdP-stcfed-IFSC";
	static String IDPMAIS_ENDPOINT = "https://idp-mais.cafeexpresso.rnp.br/RNPSecurityTokenService/RNPSTS";
	static String USERNAME1 = "joaog0t";
	static String PASSWORD1 = "joao123";
	

	static String TENANTID = "312e06f400834de395ce41e7ac28e0cc";
	
	
	@Before
	public void setUp() throws Exception {
		keystoneClient = new AuthFederatedKeystoneIDPMais(CANA_ENDPOINT);
		this.KEYSTONE_ENDPOINT = CANA_ENDPOINT;
		this.REALM = IDPMAIS_REALM;
		this.IDP_ENDPOINT = IDPMAIS_ENDPOINT;
		this.ENTITY_ID = CANA_ENTITY_ID;
		
		keystoneClient.setUsername(USERNAME1);
		keystoneClient.setPassword(PASSWORD1);
	}

	@Test
	public void testGetIdPResponse2() throws Exception {
		
		String[] idpRequest = keystoneClient.getIdPRequest(KEYSTONE_ENDPOINT, REALM);
		
		System.out.println("IdP Request");
		System.out.println("Endpoint: " + idpRequest[0]);
		System.out.println("SAMLRequest: " + idpRequest[1]);
		
		if (IDP_ENDPOINT == null) {
			IDP_ENDPOINT = idpRequest[0];
		}
		
		String response = keystoneClient.getIdPResponse(IDP_ENDPOINT, idpRequest[1]);
		
		assertNotNull(response);
		
		System.out.println("IdP response: \n" + response);
		
		fail("Not yet implemented"); // TODO
	}
	
}
