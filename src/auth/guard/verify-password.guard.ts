import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import * as argon from 'argon2';

import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class VerifyPassword implements CanActivate {
  constructor(private prisma: PrismaService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();

    const user = await this.prisma.user.findUnique({
      where: {
        email: request.body.email,
      },
    });

    if (!user) throw new ForbiddenException('User not found in the Database.');

    const comparePwd = await argon.verify(user.password, request.body.password);

    if (!comparePwd)
      throw new ForbiddenException(
        'There is an error in the entered credentials.',
      );
    const { password, ...result } = user;

    request.user = result;

    return true;
  }
}
