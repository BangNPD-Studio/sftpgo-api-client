import OpenAPIClientAxios, { AxiosRequestConfig } from 'openapi-client-axios';

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
