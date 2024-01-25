import OpenAPIClientAxios from 'openapi-client-axios';
import { Client as TypeSFTPGoAPI } from './client';

const defaultOption = {
  // definition: resolve(process.cwd(), 'src', 'assets', 'openapi.json'),
  definition:
    'https://raw.githubusercontent.com/BangNPD-Studio/sftpgo-api-client/main/assets/openapi.json',
  serverUrl: 'http://localhost:8080/api/v2',
};

export function sftpgoApiClient(options = defaultOption) {
  const api = new OpenAPIClientAxios({
    definition: options.definition,

    withServer: { url: options.serverUrl, description: 'Default server' },
  });
  return api.init<TypeSFTPGoAPI>();
}

export type { Client as TypeSFTPGoAPI } from './client';
