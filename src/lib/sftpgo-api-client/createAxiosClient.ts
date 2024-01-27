import OpenAPIClientAxios, { AxiosRequestConfig } from 'openapi-client-axios';
import { createDocument } from './createDocument';
import { TypeSFTPGoApiClientAxios } from './client';

export type CreateApiClientOptions = {
  /**
   * Url to sftpgo server
   */
  serverUrl: string;

  /**
   * Default is https://raw.githubusercontent.com/BangNPD-Studio/sftpgo-api-client/main/assets/openapi.json
   */
  definition?: string;

  /**
   * Default config for request call to get definition (If your definition is protected by api-token or password, you can add header here)
   */
  axiosConfigToLoadDefine?: AxiosRequestConfig;

  /**
   * Default config for axios to call sftpgo api
   */
  axiosConfigDefaults?: AxiosRequestConfig;
};

const defaultOption: Partial<CreateApiClientOptions> = {
  definition:
    'https://raw.githubusercontent.com/BangNPD-Studio/sftpgo-api-client/main/assets/openapi.json',
};

export async function createAxiosClient(options: CreateApiClientOptions) {
  // Load default options
  options = {
    ...defaultOption,
    ...options,
  };

  // Load definition by axiosConfigToLoadDefine
  const document = await createDocument({
    definition: options.definition,
    axiosConfigDefaults: options.axiosConfigToLoadDefine,
  });

  // Create OpenAPIClientAxios with axiosConfigDefaults
  const api = new OpenAPIClientAxios({
    definition: document,
    axiosConfigDefaults: options.axiosConfigDefaults,
    withServer: { url: options.serverUrl, description: 'Default server' },
  });

  // Return full-typed client
  return api.init<TypeSFTPGoApiClientAxios>();
}
