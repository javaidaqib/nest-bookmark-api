import { Controller, Post, Body } from '@nestjs/common';

import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { JwtResponseType } from 'types';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signup(@Body() dto: AuthDto): Promise<JwtResponseType> {
    return this.authService.signup(dto);
  }

  @Post('signin')
  signin(@Body() dto: AuthDto): Promise<JwtResponseType> {
    return this.authService.signin(dto);
  }
}
