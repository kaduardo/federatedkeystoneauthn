package federacao.idpmais;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import keystone.FederatedKeystoneTest;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;

public class AuthFederatedKeystoneIDPMaisExpTest extends FederatedKeystoneTest{

	static String CANA_ENDPOINT = "http://cana.ect.ufrn.br:5000/v2.0";
	static String CANA_ENTITY_ID = "http://cana.ect.ufrn.br:5000";
	
	static String PINGA_ENDPOINT = "https://pinga.ect.ufrn.br:5000/v2.0";
	static String PINGA_ENTITY_ID = "https://pinga.ect.ufrn.br:5000";
	
	static String PILOTO_ENTITY_ID = "https://gt-cnc2.pop-pa.rnp.br:5000/";
	
	static String IDPMAIS_REALM = "IdP-stcfed-IFSC";
	static String IDPMAIS_ENDPOINT = "https://idpstcfed.sj.ifsc.edu.br/RNPSecurityTokenService/RNPSTS";
	static String USERNAME1 = "funcionario";
	static String PASSWORD1 = "funcionario123";
	
	static String IDPMAIS_EXPRESSO_REALM = "IdP IDP1.cafeexpresso"; 
	static String IDPMAIS_EXPRESSO_ENDPOINT = "https://idp-mais.cafeexpresso.rnp.br/RNPSecurityTokenService/RNPSTS";
	static String USERNAME_EXPRESSO = "joaogt";
	static String PASSWORD_EXPRESSO = "joao123";
	

	static String TENANTID = "312e06f400834de395ce41e7ac28e0cc";
	
	
	@Before
	public void setUp() throws Exception {
		keystoneClient = new AuthFederatedKeystoneIDPMais(PINGA_ENDPOINT);
		this.KEYSTONE_ENDPOINT = PINGA_ENDPOINT;
		this.REALM = IDPMAIS_EXPRESSO_REALM;
		this.IDP_ENDPOINT = IDPMAIS_ENDPOINT;
		this.ENTITY_ID = PINGA_ENTITY_ID;
		
		keystoneClient.setUsername(USERNAME1);
		keystoneClient.setPassword(PASSWORD1);
	}

	@Test
	public void testGetIdPResponse2() throws Exception {
		
		//String[] idpRequest = keystoneClient.getIdPRequest(KEYSTONE_ENDPOINT, REALM);
		
		System.out.println("IdP Request");
		//System.out.println("Endpoint: " + idpRequest[0]);
		//System.out.println("SAMLRequest: " + idpRequest[1]);
		
		//if (IDP_ENDPOINT == null) {
		//	IDP_ENDPOINT = idpRequest[0];
		//}
		
		String response = keystoneClient.getIdPResponse(IDP_ENDPOINT, null);
		
		assertNotNull(response);
		
		System.out.println("IdP response: \n" + response);
		
		fail("Not yet implemented"); // TODO
	}
	
	@Test
	public void testGetUnscopedToken() throws Exception {
		//String[] idpRequest = keystoneClient.getIdPRequest(KEYSTONE_ENDPOINT, REALM);
		//if (IDP_ENDPOINT == null) {
		//	IDP_ENDPOINT = idpRequest[0];
		//}
		
		String idpResponse = keystoneClient.getIdPResponse(IDP_ENDPOINT, null);
		
		JSONArray tenants = keystoneClient.getUnscopedToken(KEYSTONE_ENDPOINT, idpResponse, REALM);
		assertNotNull(tenants);
		System.out.println("Printing tenants:");
		for (int i = 0; i < tenants.length(); i++) {
			JSONObject tenant = tenants.getJSONObject(i);
			assertNotNull(tenant);
			System.out.println("FriendlyName: " + tenant.getString("friendlyName") );
			System.out.println("Name: " + tenant.getString("name") );
			System.out.println("id: " + tenant.getString("id") );
		}
		
		String unscopedToken = keystoneClient.getUnescopedToken();
		assertNotNull(unscopedToken);
		System.out.println("Unscoped Token: " + unscopedToken);
		
		
		fail("Not yet implemented"); // TODO
	}
}
