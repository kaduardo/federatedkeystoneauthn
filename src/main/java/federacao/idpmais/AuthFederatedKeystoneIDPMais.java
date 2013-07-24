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
	
}
