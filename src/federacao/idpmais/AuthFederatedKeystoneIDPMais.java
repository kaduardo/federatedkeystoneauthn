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
		
		String idpResponse = idpMais.getIDPMaisSAMLResponse(
				getUsername(), 
				getPassword(), 
				idpEndpoint, 
				"http://cana.ect.ufrn.br:5000/v2.0"); 
		//TODO extract the last parameter from the idpRequest

		return idpResponse;
	}
	
	

}
