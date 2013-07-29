package keystone;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import connection.MyHttpClientTrustAll;

public abstract class FederatedKeystonePinga extends FederatedKeystone {

	public FederatedKeystonePinga() {
		this(null);
	}

	public FederatedKeystonePinga(String keystoneEndpoint) {
		this.setHttpClient(new MyHttpClientTrustAll());
	}

	public String buildIdpRequestJson(String realm) {
		String json = "{\"realm\":"
				+ realm + "}";
		return json;
	}

	public String buildUnscopedTokenJson(String realm, String idpResponse) throws UnsupportedEncodingException {
		String json = "{" +
				"\"realm\" : " + realm + ", " + 
				" \"idpResponse\" : \"SAMLResponse=" + 
						URLEncoder.encode(idpResponse, "UTF-8") + "\"" +
				"}";

		return json;
	}








}
