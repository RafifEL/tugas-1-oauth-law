import { Request } from 'express';

export interface OauthLogin extends Request {
  body: {
    username: string;
    password: string;
    grant_type: string;
    client_id: string;
    client_secret: string;
  };
}
