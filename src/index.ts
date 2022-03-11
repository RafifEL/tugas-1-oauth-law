import express from 'express';
import HmacSHA1 from 'crypto-js/hmac-sha1';
import { OauthLogin } from './interface';
import Redis from './utils/redis';

const TOKEN_SECRET =
  process.env.TOKEN_SECRET || '07eb58372a3e8ba8426067100abd595d29545d0b';

const users = [
  {
    user_id: 'budiSetia',
    full_name: 'Budi Setiawan',
    password: 'budiAdalahBudiman',
    npm: '1803207722',
  },
];

const clients = [
  {
    client_id: '1c488d34-9b8b-4c21-9c7f-ad3b11775f21',
    client_secret: '0b8d48225edbc211d132517ea00ceffa4b87b528',
  },
];

const app = express();
app.use(express.json());
app.use(
  express.urlencoded({
    extended: true,
  })
);

app.post('/oauth/token', async (req: OauthLogin, res) => {
  const { username, password, client_id, client_secret, grant_type } = req.body;

  const objectError = {
    error: 'invalid_request',
    error_description: 'ada kesalahan masbro!',
  };

  try {
    if (grant_type !== 'password') return res.status(401).json(objectError);

    const client = clients.filter(
      client =>
        client.client_id === client_id && client.client_secret === client_secret
    )[0];

    if (!client) return res.status(401).json(objectError);

    const user = users.filter(user => user.user_id === username)[0];

    if (!user) return res.status(401).json(objectError);

    const passwordMatch = user.password === password;

    if (!passwordMatch) return res.status(401).json(objectError);

    const iat = new Date();

    const accessToken = HmacSHA1(
      JSON.stringify({
        user_id: user.user_id,
        client_id,
        client_secret,
        iat,
        expires_in: 300,
      }),
      TOKEN_SECRET
    ).toString();

    const refreshToken = HmacSHA1(
      JSON.stringify({
        user_id: user.user_id,
        client_id,
        client_secret,
        iat,
        expires_in: 2 * 24 * 60 * 60,
      }),
      TOKEN_SECRET
    ).toString();

    const redisTokenPayload = {
      access_token: accessToken,
      client_id,
      user_id: user.user_id,
      full_name: user.full_name,
      npm: user.npm,
      expires: null,
      refresh_token: refreshToken,
    };

    const redis = await Redis.getInstance();
    await redis.setKeyWithExpiry(
      'accessToken',
      accessToken,
      JSON.stringify(redisTokenPayload),
      300
    );

    await redis.setKeyWithExpiry(
      'refreshToken',
      refreshToken,
      JSON.stringify(redisTokenPayload),
      2 * 24 * 60 * 60
    );

    return res.json({
      access_token: accessToken,
      expires_in: 300,
      token_type: 'Bearer',
      scope: null,
      refresh_token: refreshToken,
    });
  } catch (err) {
    console.log(err);
    return res.status(401).json(objectError);
  }
});

app.post('/oauth/resource', async (req, res) => {
  const objectError = {
    error: 'invalid_token',
    error_description: 'Token Salah masbro',
  };

  try {
    const { authorization } = req.headers;
    if (!authorization) {
      return res.status(401).json(objectError);
    }
    const [method, token] = authorization?.split(' ');

    if (method !== 'Bearer') {
      return res.status(401).json(objectError);
    }

    const redis = await Redis.getInstance();
    const tokenPayload = await redis.getKey('accessToken', token);

    if (!tokenPayload) {
      return res.status(401).json(objectError);
    }

    const parsedTokenPayload = JSON.parse(tokenPayload);
    return res.json({ ...parsedTokenPayload });
  } catch (err) {
    console.log(err);
    return res.status(401).json(objectError);
  }
});

app.listen(3000, () => {
  console.log('App start at port 3000');
});
