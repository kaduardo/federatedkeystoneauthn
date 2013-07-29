package keystone;

import static org.junit.Assert.*;

import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;

public abstract class FederatedKeystoneTest {

	protected FederatedKeystone keystoneClient;
	
	//Those must be set by the setUp method of subclasses
	protected String KEYSTONE_ENDPOINT = null;
	protected String REALM = null;
	protected String ENTITY_ID = null;
	protected String IDP_ENDPOINT = null;
	protected String TENANT_ID = null;

	protected String selectedRealm = null;
	
	@Before
	public void setUp() throws Exception {
		this.selectedRealm = null;
	}
	
	@Test
	public void testGetRealmList() throws Exception {
		List<String> realms = keystoneClient.getRealmList(KEYSTONE_ENDPOINT);
		
		assertTrue("Empty realms returned by keystone", (realms.size() > 0));
		
		processRealm(realms);
	}

	public abstract void processRealm(List<String> realms);
	
	@Test
	public void testGetIdPRequest() throws Exception {
		List<String> realms = keystoneClient.getRealmList(KEYSTONE_ENDPOINT);		
		assertTrue("Empty realms returned by keystone", (realms.size() > 0));
		processRealm(realms);
		
		String[] response = keystoneClient.getIdPRequest(KEYSTONE_ENDPOINT, selectedRealm);
		
		assertTrue("Wrong number of elements in the return", (response.length == 2));
		
		//the endpoint
		assertNotNull(response[0]);
		System.out.println("IdP Endpoint: " + response[0]);

		//the request
		assertNotNull(response[1]);
		System.out.println("IdP Request: \n" + response[1]);
		
		String entityID = keystoneClient.getEntityID(response[1]);
		assertNotNull(entityID);
		System.out.println("EntityID: " + entityID);
		assertEquals(ENTITY_ID, entityID);
		
	}

	@Test
	public void testGetIdPResponse() throws Exception {
		List<String> realms = keystoneClient.getRealmList(KEYSTONE_ENDPOINT);		
		assertTrue("Empty realms returned by keystone", (realms.size() > 0));
		processRealm(realms);
		String[] idpRequest = keystoneClient.getIdPRequest(KEYSTONE_ENDPOINT, selectedRealm);
		
		if (IDP_ENDPOINT == null) {
			IDP_ENDPOINT = idpRequest[0];
		}
		
		System.out.println("Authenticating on IDP " + IDP_ENDPOINT);
		System.out.println("With " + idpRequest[1]);
		
		String response = keystoneClient.getIdPResponse(IDP_ENDPOINT, idpRequest[1]);
		
		assertNotNull(response);
		
		System.out.println("IdP response: \n" + response);
		//TODO decodificar a resposta e comparar usando dados do IDP Request
	}
	
	@Test
	public void testGetUnscopedToken() throws Exception {
		List<String> realms = keystoneClient.getRealmList(KEYSTONE_ENDPOINT);	
		assertTrue("Empty realms returned by keystone", (realms.size() > 0));
		processRealm(realms);
		String[] idpRequest = keystoneClient.getIdPRequest(KEYSTONE_ENDPOINT, selectedRealm);

		if (IDP_ENDPOINT == null) {
			IDP_ENDPOINT = idpRequest[0];
		}
		
		String idpResponse = keystoneClient.getIdPResponse(IDP_ENDPOINT, idpRequest[1]);
		
		JSONArray tenants = keystoneClient.getUnscopedToken(KEYSTONE_ENDPOINT, idpResponse, selectedRealm);
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
		//TODO testar se os tenants retornados sao os esperados
	}

	@Test
	public void testSwapTokens() throws Exception {
		String[] idpRequest = keystoneClient.getIdPRequest(KEYSTONE_ENDPOINT, REALM);
		if (IDP_ENDPOINT == null) {
			IDP_ENDPOINT = idpRequest[0];
		}
		
		String idpResponse = keystoneClient.getIdPResponse(IDP_ENDPOINT, idpRequest[1]);
		
		JSONArray tenants = keystoneClient.getUnscopedToken(KEYSTONE_ENDPOINT, idpResponse, REALM);
		assertNotNull(tenants);
		
		String unscopedToken = keystoneClient.getUnescopedToken();
		assertNotNull(unscopedToken);
		System.out.println("Unscoped Token: " + unscopedToken);
		
		String scopedToken = keystoneClient.swapTokens(KEYSTONE_ENDPOINT, unscopedToken, tenants.getJSONObject(0).getString("id") );
		assertNotNull(scopedToken);
		System.out.println("Scoped Token: " + scopedToken);
		
	}

}
