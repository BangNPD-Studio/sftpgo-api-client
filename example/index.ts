import { createWriteStream } from 'fs';
import {
  SFTPGoApiClient,
  createAxiosClient,
} from '../dist/sftpgo-api-client/src/index';
import { resolve } from 'path';

async function testOnlyApiClient() {
  const axiosClient = await createAxiosClient({
    serverUrl: 'http://localhost:8080/api/v2',
  });
  const response = await axiosClient.get_user_token(undefined, undefined, {
    auth: {
      username: 'public',
      password: '12345678',
    },
  });
  if (response.data != null) {
    console.log('Test successfull!!!');
    console.log({
      data: response.data,
    });
  }
}

async function testClassApiClientWithAuth() {
  const client = new SFTPGoApiClient({
    createApiClientOption: {
      serverUrl: 'http://localhost:8080/api/v2',
    },
    auth: {
      username: 'public',
      password: '12345678',
    },
  });

  // Call this method before each request to ensure access token
  await client.ensureToken();

  // Not need auth header, the instance already set it
  const response = await client.axiosClient.download_user_file(
    {
      path: '/test/api/bg-login-2.png',
    },
    undefined,
    {
      responseType: 'stream',
    }
  );

  // Save result to local
  const destFile = createWriteStream(
    resolve(process.cwd(), 'example', 'tmp', 'bg-login-2.png')
  );
  response.data.pipe(destFile);
  destFile.on('close', () => {
    console.log('Test successfull!!!');
  });
}

async function testClassApiClientWithAuthAdmin() {
  const client = new SFTPGoApiClient({
    createApiClientOption: {
      serverUrl: 'http://localhost:8080/api/v2',
    },
    auth: {
      username: 'admin',
      password: '12345678',
      role: 'admin',
    },
  });

  // Call this method before each request to ensure access token
  await client.ensureToken();

  // Not need auth header, the instance already set it
  const response = await client.axiosClient.get_admin_profile();

  if (response.data != null) {
    console.log('Test successfull!!!');
    console.log({
      data: response.data,
    });
  }
}

async function test() {
  await testOnlyApiClient();
  await testClassApiClientWithAuth();
  await testClassApiClientWithAuthAdmin();
}

test();
