import { AxiosResponse } from 'axios';
import { TypeSFTPGoApiClient, TypeSFTPGoApiClientAxios } from './client';
import { CreateApiClientOptions, createAxiosClient } from './createAxiosClient';

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
    /**
     * Role to login SFTPGo. Default is user
     */
    role?: 'admin' | 'user';
  };
};

const defaultAuth: Partial<SFTPGoApiClientOptions['auth']> = {
  role: 'user',
};

/**
 * Class to help call SFTPGo API with automatic handle access-token. Check example at https://github.com/BangNPD-Studio/sftpgo-api-client/tree/main/example
 * Not support two factor authentication yet
 */
export class SFTPGoApiClient {
  expiredAt: Date;
  axiosClient: TypeSFTPGoApiClientAxios;

  constructor(private options: SFTPGoApiClientOptions) {
    // Load default auth for options
    options.auth = { ...defaultAuth, ...options.auth };
  }

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
    let response: AxiosResponse<
      TypeSFTPGoApiClient.Components.Schemas.Token,
      any
    >;

    if (this.options.auth.role == 'admin') {
      response = await this.axiosClient.get_token(undefined, undefined, {
        auth: this.options.auth,
      });
    } else {
      response = await this.axiosClient.get_user_token(undefined, undefined, {
        auth: this.options.auth,
      });
    }

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
