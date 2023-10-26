import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as argon from 'argon2';

import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import { JwtResponseType } from 'types';

@Injectable({})
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signup(dto: AuthDto) {
    try {
      // create the hash password
      const hashedPwd = await argon.hash(dto.password);

      // save the  user in the db
      const savedUser = await this.prisma.user.create({
        data: {
          email: dto.email,
          password: hashedPwd,
        },
      });

      return this.signToken(savedUser.id, savedUser.email);
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code == 'P2002') {
          throw new ForbiddenException('User already exists in the Database.');
        }
      }
      throw error;
    }
  }

  async signin(dto: AuthDto) {
    // search for the user in the DB
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    // if not found then return an exception
    if (!user) throw new ForbiddenException('User not found in the Database.');

    // compare the user plain pwd with hashed pwd
    const comparePwd = await argon.verify(user.password, dto.password);

    // if not matched then return an exception
    if (!comparePwd)
      throw new ForbiddenException(
        'There is an error in the entered credentials.',
      );
    return this.signToken(user.id, user.email);
  }

  // JWT signing function
  async signToken(userId: number, userEmail: string): Promise<JwtResponseType> {
    const payload = { sub: userId, email: userEmail };

    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: this.config.get('JWT_SECRET'),
    });

    return { access_token: token };
  }
}
