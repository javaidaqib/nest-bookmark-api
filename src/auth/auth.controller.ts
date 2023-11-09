import {
  Controller,
  Post,
  Body,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { User } from '@prisma/client';

import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { JwtResponseType } from 'types';
import { VerifyPassword } from './guard/verify-password.guard';
import { GetUser } from './decorator';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @HttpCode(HttpStatus.CREATED)
  @Post('signup')
  signup(@Body() dto: AuthDto): Promise<JwtResponseType> {
    return this.authService.signup(dto);
  }

  @HttpCode(HttpStatus.OK)
  @UseGuards(VerifyPassword)
  @Post('signin')
  signin(@GetUser() user: User): Promise<JwtResponseType> {
    return this.authService.signin(user);
  }
}
