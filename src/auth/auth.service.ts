import { Injectable } from '@nestjs/common';

@Injectable({})
export class AuthService {
  signup() {
    return 'I have signed up!';
  }

  signin() {
    return 'I have signed in';
  }
}
