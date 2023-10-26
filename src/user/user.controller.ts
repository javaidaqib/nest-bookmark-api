import { Controller, UseGuards, Get, Req } from '@nestjs/common';
import { User } from '@prisma/client';
import { GetUser } from 'src/auth/decorator';
import { JwtGuard } from 'src/auth/guard';

@Controller('users')
export class UserController {
  constructor() {}

  @UseGuards(JwtGuard)
  @Get('me')
  test(@GetUser() user: User) {
    return user;
  }
}
