import OpenAPIClientAxios from 'openapi-client-axios';
import { Client as AxiosClient } from './client';

const defaultOption = {
  definition: 'https://raw.githubusercontent.com/drakkan/sftpgo/main/openapi/openapi.yaml',
  serverUrl: 'http://localhost:8080/api/v2'
}

export function sftpgoApiClient(options = defaultOption) {
  const api = new OpenAPIClientAxios({ definition: options.definition, withServer: { url: options.serverUrl, description: 'Default server' }});
  return api.init<AxiosClient>();
}
