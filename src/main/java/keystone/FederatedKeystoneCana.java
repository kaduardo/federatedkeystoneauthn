package keystone;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import connection.MyHttpClientTrustAll;

public abstract class FederatedKeystoneCana extends FederatedKeystone {

	public FederatedKeystoneCana() {
		this(null);
	}

	public FederatedKeystoneCana(String keystoneEndpoint) {
		this.setHttpClient(new MyHttpClientTrustAll());
	}

	public String buildIdpRequestJson(String realm) {
		String json = "{\"realm\": {\"name\": \""
				+ realm + "\"}}";
		return json;
	}

	public String buildUnscopedTokenJson(String realm, String idpResponse) throws UnsupportedEncodingException {
		String json = "{" +
				"\"realm\" : {\"name\":\"" + realm + "\"}, " + 
				" \"idpResponse\" : \"SAMLResponse=" + 
						URLEncoder.encode(idpResponse, "UTF-8") + "\"" +
				"}";

		return json;
	}

}
