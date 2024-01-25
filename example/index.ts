import { sftpgoApiClient } from '../lib/sftpgo-api-client';

async function start() {
  const client = await sftpgoApiClient();
  const response = await client.get_user_token(undefined, undefined, {
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

start();
