package federacao.idpmais;

import static org.junit.Assert.*;
import keystone.FederatedKeystoneTest;

import org.junit.Before;
import org.junit.Test;

public class AuthFederatedKeystoneIDPMaisTest extends FederatedKeystoneTest{

	static String CANA_ENDPOINT = "http://cana.ect.ufrn.br:5000/v2.0";
	
	static String IDPMAIS_REALM = "IdP-stcfed-IFSC";
	static String IDPMAIS_ENDPOINT = "http://idpstcfed.sj.ifsc.edu.br/RNPSecurityTokenService/RNPSTS";
	static String USERNAME1 = "funcionario";
	static String PASSWORD1 = "funcionario123";
	

	static String TENANTID = "312e06f400834de395ce41e7ac28e0cc";
	
	
	@Before
	public void setUp() throws Exception {
		keystoneClient = new AuthFederatedKeystoneIDPMais(CANA_ENDPOINT);
		this.KEYSTONE_ENDPOINT = CANA_ENDPOINT;
		this.REALM = IDPMAIS_REALM;
		this.IDP_ENDPOINT = IDPMAIS_ENDPOINT;
		
		keystoneClient.setUsername(USERNAME1);
		keystoneClient.setPassword(PASSWORD1);
	}

	@Test
	public void testGetIdPResponse() throws Exception {
		
		String[] idpRequest = keystoneClient.getIdPRequest(KEYSTONE_ENDPOINT, REALM);
		
		String response = keystoneClient.getIdPResponse(IDP_ENDPOINT, idpRequest[1]);
		
		assertNotNull(response);
		
		System.out.println("IdP+ response: \n" + response);
		
		fail("Not yet implemented"); // TODO
	}

}
