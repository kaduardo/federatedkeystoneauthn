package federacao;

import java.util.ArrayList;
import java.util.List;

import keystone.FederatedKeystone;

import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.ExecutionContext;
import org.apache.http.protocol.HTTP;
import org.apache.http.protocol.HttpContext;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import connection.OurUtil;

public class AuthFederatedKeystone extends FederatedKeystone {

	static String KEYSTONE_ENDPOINT = "http://cana.ect.ufrn.br:5000/v2.0";

	public AuthFederatedKeystone(String keystoneEndpoint) {
		super(keystoneEndpoint);
	}

	/**
	 * This method will send the SAML received from SP to the selected IDP, that
	 * will return a IDP specific login html page. Then the user's credentials
	 * are submited to the IDP the same way the page would. As a response, the
	 * IDP sends a HTML page containing a SAML
	 * 
	 * @param endpoint the endpoint of the IDP
	 * @param idpRequest the SAML request in a base64 urlencoded format
	 * @return SAMLResponse to be sent to the SP
	 */
	@Override
	public String getIdPResponse(String idpEndpoint, String idpRequest) throws Exception {

		System.out.println("sending SAML request to IDP endpoint: \n"
				+ idpEndpoint + idpRequest);
		HttpGet httpGet = new HttpGet(idpEndpoint + idpRequest);

		try {
			HttpContext context = new BasicHttpContext();

			// vai pegar a resposta de requisicao, que uma pagina HTML
			HttpResponse requestResp = getHttpClient()
					.execute(httpGet, context);

			// transforma resposta em uma string contendo o json da resposta
			String responseAsString = OurUtil.httpEntityToString(requestResp
					.getEntity());

			HttpUriRequest currentReq = (HttpUriRequest) context
					.getAttribute(ExecutionContext.HTTP_REQUEST);
			HttpHost currentHost = (HttpHost) context
					.getAttribute(ExecutionContext.HTTP_TARGET_HOST);
			String currentUrl = currentHost.toURI() + currentReq.getURI();

			// Transforma o html recebido na requisio anterior
			Document idpDoc = Jsoup.parse(responseAsString);

			// Pega o componente HTML "form" que contem o formulrio de insero de
			// login e senha do usuario
			Element idpFormElement = idpDoc.select("form").get(0);

			/** Submitting user+password form **/

			HttpPost httpPost2 = new HttpPost(currentUrl);
			List<NameValuePair> nameValuePairs2 = new ArrayList<NameValuePair>();
			nameValuePairs2.add(new BasicNameValuePair("username", getUsername()));
			nameValuePairs2.add(new BasicNameValuePair("password", getPassword()));
			httpPost2.setEntity(new UrlEncodedFormEntity(nameValuePairs2, "UTF-8"));
			HttpResponse response2 = getHttpClient().execute(httpPost2);
			String authResponseHtml = OurUtil.httpEntityToString(response2
					.getEntity());

			System.out.println("\nauthResponse\n" + authResponseHtml);

			// System.out.println("*************Cookies after GETTING SAMLresponse FROM IDP*************");
			//
			// for(Cookie cookie:
			// userSpecificHttpClient.getCookieStore().getCookies()){
			// System.out.println("cookie name: "+ cookie.getName());
			// System.out.println("cookie value: "+ cookie.getValue());
			// System.out.println("cookie toString: "+ cookie.toString());
			// System.out.println("cookie toString: ");
			// }
			//
			// System.out.println("***************************************");
			//
			// Transforma o html recebido na requisio anterior
			Document idpDoc2 = Jsoup.parse(authResponseHtml);

			// Pega o componente HTML "form" que contm o formulrio de insero de
			// login e senha do usurio
			Element idpSAMLresponse = idpDoc2.select("input").get(1);
			// System.out.println("PEGOU SAMLRESP "+
			// idpSAMLresponse.attr("value"));
			return idpSAMLresponse.attr("value");
		} finally {
			httpGet.abort();
		}

	}

}
