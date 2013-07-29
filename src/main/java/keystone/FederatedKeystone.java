package keystone;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.json.JSONArray;
import org.json.JSONObject;

import connection.OurUtil;

public abstract class FederatedKeystone {
	private DefaultHttpClient httpClient;

	private String keystoneEndpoint;
	private String realm;

	private String username;
	private String password;

	private String samlRequest;
	private String samlResponse;

	private String unescopedToken;
	private String token;
	
	
	public List<String> getRealmList(String keystoneEndpoint) throws Exception {

		HttpPost httpPostRequest = new HttpPost(keystoneEndpoint);
		try {

			// cria json sem conteudo e o insere no corpo (body) da requisicao
			StringEntity entity = new StringEntity("{}");

			entity.setContentType("application/json");
			httpPostRequest.setEntity(entity);
			httpPostRequest.addHeader("Content-type", "application/json");
			httpPostRequest.addHeader("X-Authentication-Type", "federated");

			System.out.println("getRealmList() - request: " + httpPostRequest.toString());

			// vai tratar a resposta da requisio
			HttpResponse resp = getHttpClient().execute(httpPostRequest);

			// transforma resposta em uma string contendo o json da resposta
			String response = OurUtil.httpEntityToString(resp.getEntity());
			System.out.println("getRealmList() - Response: \n" + response);
			JSONObject jsonResp = new JSONObject(response);

			// OBS.: realm=IDP
			JSONArray realms = jsonResp.getJSONArray("realms");

			ArrayList<String> idps = new ArrayList<String>();

			for (int i = 0; i < realms.length(); ++i) {
				JSONObject realm = realms.getJSONObject(i);
				idps.add(realm.toString() );
			}

			return idps;
		} finally {
			httpPostRequest.abort();
		}
	}

	public abstract String buildIdpRequestJson(String realm);
	
	public String[] getIdPRequest(String keystoneEndpoint, String realm)
			throws Exception {
		String[] responses = new String[2];
		HttpPost httpPost = new HttpPost(keystoneEndpoint);

		this.setRealm(realm);

		try {

			// cria json com crenciais para requisitar autentica����o
			String json = buildIdpRequestJson(realm);
			System.out.println("Json to send: \n" + json);
			
			StringEntity entity = new StringEntity(json);

			entity.setContentType("application/json");
			httpPost.setEntity(entity);
			httpPost.addHeader("Content-type", "application/json");
			httpPost.addHeader("X-Authentication-Type", "federated");

			// vai tratar a resposta da requisi����o
			HttpResponse resp = getHttpClient().execute(httpPost);

			// transforma resposta em uma string contendo o json da resposta
			String responseAsString = httpEntityToString(resp.getEntity());
			System.out.println("Resposta idpRequest: \n" + responseAsString);
			JSONObject jsonResp = new JSONObject(responseAsString);

			responses[0] = jsonResp.getString("idpEndpoint");
			responses[1] = jsonResp.getString("idpRequest");

			this.setSamlRequest(responses[1]);

			return responses;
		} finally {
			httpPost.abort();
		}

	}
	
	
	public abstract String getIdPResponse(String idpEndpoint, String idpRequest)
			throws Exception;
	
	
	public abstract String buildUnscopedTokenJson(String realm, String idpResponse) throws UnsupportedEncodingException ;
	
	public JSONArray getUnscopedToken(String keystoneEndpoint,
			String idpResponse, String realm) throws Exception {
		System.out.println("getUnscopedToken - endpoint: "
				+ keystoneEndpoint);
		System.out
				.println("getUnscopedToken - idpResponse: " + idpResponse);
		System.out.println("getUnscopedToken - realm: " + realm);

		HttpPost httppost = new HttpPost(keystoneEndpoint);

		try {
			// Debug
			String samlDecoded = new String(Base64.decodeBase64(idpResponse
					.getBytes("UTF-8")));
			System.out.println("\n\n<INI>>>Saml decoded: \n\n" + samlDecoded
					+ "\n <FIM DECODED>>>>>>");
			// End Debug

			String jsonRequest = buildUnscopedTokenJson(realm, idpResponse);
			StringEntity entity = new StringEntity(jsonRequest);

			System.out.println("getUnscopedToken - JSON TO SEND:\n"
					+ httpEntityToString(entity) );
			entity.setContentType("application/json");
			httppost.setEntity(entity);
			httppost.addHeader("Content-type", "application/json");
			httppost.addHeader("X-Authentication-Type", "federated");

			// vai tratar a resposta da requisicao
			HttpResponse requestResp = getHttpClient().execute(httppost);
			System.out.println("Http post sendSAMlrespToKeystone executed ");

			// transforma resposta em uma string contendo o json da resposta
			String responseAsString = httpEntityToString(requestResp
					.getEntity());
			System.out.println("\n\ngetUnscopedToken Keystone response:\n"
					+ responseAsString);

			JSONObject jsonResp = new JSONObject(responseAsString);

			// Recover the unescoped token
			this.setUnescopedToken(jsonResp.getString("unscopedToken"));

			// Recover the list of tenants
			JSONArray result = jsonResp.getJSONArray("tenants");
			return result;
		} finally {
			httppost.abort();
		}

	}
	
	public void getScopedToken(String keystoneEndpoint, String idpResponse,
			String tenantFn) {
		throw new RuntimeException("not implemented"); 
	}
	
	public String swapTokens(String keystoneEndpoint, String unscopedToken,
			String tenantId) throws Exception {

		HttpPost httpPostRequest = new HttpPost(keystoneEndpoint + "/tokens");

		try {
			StringEntity entity = new StringEntity("{\"auth\" : "
					+ "{\"token\" : " + "{\"id\" : \"" + unscopedToken
					+ "\"}, " + " \"tenantId\" : \"" + tenantId + "\"" + "}"
					+ "}");
			entity.setContentType("application/json");
			httpPostRequest.setEntity(entity);
			httpPostRequest.addHeader("Content-type", "application/json");

			HttpResponse keystoneResponse = getHttpClient().execute(httpPostRequest);

			String responseAsString = OurUtil
					.httpEntityToString(keystoneResponse.getEntity());

			System.out.println("\n\nKeystone Scoped TOKEN:\n"
					+ responseAsString);

			return responseAsString;

		} finally {
			httpPostRequest.abort();
		}
	}
	
	/**
	 * Converts a HttpEntity to String format
	 * 
	 * @param ent
	 * @return
	 */
	public static String httpEntityToString(HttpEntity ent) {
		try {
			InputStream in = ent.getContent();
			InputStreamReader reader = new InputStreamReader(in);
			BufferedReader bfReader = new BufferedReader(reader);
			String s, content;
			StringBuilder contentBuilder = new StringBuilder();
			while ((s = bfReader.readLine()) != null) {
				contentBuilder.append(s);
			}
			content = contentBuilder.toString();
			// System.out.println("Entity content" + content);
			return content;
		} catch (IOException ex) {
			System.out
					.println("Error while checking keystone authentication response");
			return null;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	//TODO improve this method to use SAML objects
	protected String getEntityID(String samlRequest)
			throws UnsupportedEncodingException, DataFormatException,
			DecoderException, IOException {
	
		//TODO Confirm where this 13 comes from
		int index = (samlRequest.startsWith("?")?13:12);
		String saml = samlRequest.substring(index, samlRequest.length());
		String samlDecodedURL = URLDecoder.decode(saml, "UTF-8");
		
		Base64 decoder = new Base64();
		byte[] decodeBytes = decoder.decode(samlDecodedURL);

		Inflater inflater = new Inflater(true);
		inflater.setInput(decodeBytes);
		
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream(decodeBytes.length);
		byte[] buffer = new byte[1024];
		while(!inflater.finished()) {
			int count = inflater.inflate(buffer);
			outputStream.write(buffer, 0, count);
		}
		outputStream.close();
		byte[] inflatedMessage = outputStream.toByteArray();

		String decodedResponse = new String(inflatedMessage, 0, inflatedMessage.length,
				"UTF-8");

		String entityID = this
				.recuperarEntityID(decodedResponse, "saml:Issuer");

		return entityID;
	}

	private String recuperarEntityID(String fonte, String tagName) {
		String retorno = "";
		if (fonte.contains(tagName)) {
			int ini = fonte.indexOf("<" + tagName);
			int fim = fonte.indexOf("</" + tagName, ini) + tagName.length() + 3;
			String tag = fonte.substring(ini, fim);
			retorno = tag.substring(13, tag.length() - 15);
		}
		return retorno;
	}
	
	
	
	public DefaultHttpClient getHttpClient() {
		return httpClient;
	}

	public void setHttpClient(DefaultHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	public String getKeystoneEndpoint() {
		return keystoneEndpoint;
	}

	public void setKeystoneEndpoint(String keystoneEndpoint) {
		this.keystoneEndpoint = keystoneEndpoint;
	}

	public String getRealm() {
		return realm;
	}

	public void setRealm(String realm) {
		this.realm = realm;
	}

	public String getSamlRequest() {
		return samlRequest;
	}

	public void setSamlRequest(String samlRequest) {
		this.samlRequest = samlRequest;
	}

	public String getSamlResponse() {
		return samlResponse;
	}

	public void setSamlResponse(String samlResponse) {
		this.samlResponse = samlResponse;
	}

	public String getUnescopedToken() {
		return unescopedToken;
	}

	public void setUnescopedToken(String unescopedToken) {
		this.unescopedToken = unescopedToken;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
}
