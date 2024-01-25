import { sftpgoApiClient } from "../lib/sftpgo-api-client";

async function start(){
  const client = await sftpgoApiClient();
  const response = await client.get_user_token(undefined, undefined, {
    auth: {
      username: 'public',
      password: '12345678'
    }
  });
  console.log(response);
  // if (response.data != null) {
  //   console.log({
  //     data: response.data
  //   })
  // }
}

start();