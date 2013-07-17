package federacao.idpmais;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;

import keystone.FederatedKeystone;
import br.rnp.stcfed.sts.client.impl.IDPMaisClient;

public class AuthFederatedKeystoneIDPMais extends FederatedKeystone {
	
	IDPMaisClient idpMais;
	
	public AuthFederatedKeystoneIDPMais(String keystoneEndpoint) {
		super(keystoneEndpoint);
		
		idpMais = new IDPMaisClient();
	}
	
	@Override
	public String getIdPResponse(String idpEndpoint, String idpRequest) throws Exception {
		
		String entityID = getEntityID(idpRequest);
		
		String idpResponse = idpMais.getIDPMaisSAMLResponse(
				getUsername(), 
				getPassword(), 
				idpEndpoint, 
				entityID); 

		return idpResponse;
	}
	
	//TODO improve this method to use SAML objects
	private String getEntityID(String samlRequest)
			throws UnsupportedEncodingException, DataFormatException,
			DecoderException {
		String saml = samlRequest.substring(12, samlRequest.length());
		String samlDecodedURL = URLDecoder.decode(saml);
		Base64 decoder = new Base64();
		byte[] decodeBytes = decoder.decode(samlDecodedURL);

		Inflater inflater = new Inflater(true);
		inflater.setInput(decodeBytes);
		byte[] xmlMessageBytes = new byte[5000];
		int resultLength = inflater.inflate(xmlMessageBytes);

		if (!inflater.finished()) {
			throw new RuntimeException("didn't allocate enough space to hold "
					+ "decompressed data");
		}

		inflater.end();

		String decodedResponse = new String(xmlMessageBytes, 0, resultLength,
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
}
