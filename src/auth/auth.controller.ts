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
import { VerifyPassword } from './guard/verify-password.guard';
import { GetUser } from './decorator';
import { jwtPayload } from './types';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @HttpCode(HttpStatus.CREATED)
  @Post('signup')
  signup(@Body() dto: AuthDto): Promise<jwtPayload> {
    return this.authService.signup(dto);
  }

  @HttpCode(HttpStatus.OK)
  @UseGuards(VerifyPassword)
  @Post('signin')
  signin(@GetUser() user: User): Promise<jwtPayload> {
    return this.authService.signin(user);
  }
}
