import OpenAPIClientAxios, { AxiosRequestConfig } from 'openapi-client-axios';
import { Client as TypeSFTPGoApiClientAxios } from './client';
export type { Client as TypeSFTPGoApiClientAxios } from './client';

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

export type CreateDocumentOptions = {
  definition: string;
  axiosConfigDefaults?: AxiosRequestConfig;
};

export async function createDocument(options: CreateDocumentOptions) {
  const api = new OpenAPIClientAxios({
    definition: options.definition,
    axiosConfigDefaults: options.axiosConfigDefaults,
  });
  const document = await api.loadDocument();
  return document;
}

export type SFTPGoApiClientOptions = {
  /** Option to create OpenAPIClientAxios. MUST NOT override axiosConfigDefaults.headers.Authorization */
  createApiClientOption: CreateApiClientOptions;
  /**
   * Account to login SFTPGo
   */
  auth: {
    /**
     * Username to login SFTPGo
     */
    username: string;
    /**
     * Password to login SFTPGo
     */
    password: string;
  };
};

/**
 * Class to help call SFTPGo API with automatic handle access-token. Check example at https://github.com/BangNPD-Studio/sftpgo-api-client/tree/main/example
 */
export class SFTPGoApiClient {
  expiredAt: Date;
  axiosClient: TypeSFTPGoApiClientAxios;

  constructor(private options: SFTPGoApiClientOptions) {}

  async init() {
    this.axiosClient = await createAxiosClient({
      ...this.options.createApiClientOption,
    });
  }

  async ensureToken() {
    if (this.axiosClient == undefined) {
      await this.init();
    }
    if (this.expiredAt == undefined || this.expiredAt < new Date()) {
      await this.refreshToken();
    }
  }

  async refreshToken() {
    const response = await this.axiosClient.get_user_token(
      undefined,
      undefined,
      {
        auth: this.options.auth,
      }
    );

    if (response.data != null) {
      const accessToken = response.data.access_token;
      this.expiredAt = new Date(response.data.expires_at!);

      // Create new axios instance to set authorization header
      this.axiosClient = await createAxiosClient({
        ...this.options.createApiClientOption,
        axiosConfigDefaults: {
          ...this.options.createApiClientOption.axiosConfigDefaults,
          headers: {
            ...this.options.createApiClientOption.axiosConfigDefaults?.headers,
            Authorization: `Bearer ${accessToken}`,
          },
        },
      });
    }
  }
}
