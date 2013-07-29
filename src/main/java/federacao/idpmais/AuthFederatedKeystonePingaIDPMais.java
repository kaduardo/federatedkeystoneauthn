package federacao.idpmais;

import keystone.FederatedKeystonePinga;
import br.rnp.stcfed.sts.client.impl.IDPMaisClient;

public class AuthFederatedKeystonePingaIDPMais extends FederatedKeystonePinga {
	
	IDPMaisClient idpMais;
	
	public AuthFederatedKeystonePingaIDPMais(String keystoneEndpoint) {
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
