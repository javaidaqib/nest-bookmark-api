import {
  Controller,
  UseGuards,
  Get,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { User } from '@prisma/client';
import { GetUser } from 'src/auth/decorator';
import { JwtGuard } from 'src/auth/guard';

@Controller('users')
export class UserController {
  constructor() {}

  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtGuard)
  @Get('me')
  test(@GetUser() user: User, @GetUser('email') email: string) {
    return user;
  }
}
