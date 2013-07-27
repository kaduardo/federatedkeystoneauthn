package federacao.idpmais;

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
