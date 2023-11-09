import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { User } from '@prisma/client';
import * as argon from 'argon2';

import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import { jwtPayload } from './types';

@Injectable({})
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signup(dto: AuthDto): Promise<jwtPayload> {
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

      // getting the access and refresh token using the User Id and Email
      const tokens = await this.signTokens(savedUser.id, savedUser.email);
      // updating the refresh token in the user object inside the database
      await this.updateHashRT(savedUser.id, tokens.refresh_token);

      return tokens;
    } catch (error) {
      // returning the exception when there is already a user in the database
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code == 'P2002') {
          throw new ForbiddenException('User already exists in the Database.');
        }
      }
      throw error;
    }
  }

  async signin(user: User): Promise<jwtPayload> {
    // getting the access and refresh token using the User Id and Email
    const tokens = await this.signTokens(user.id, user.email);
    // updating the refresh token in the user object inside the database
    await this.updateHashRT(user.id, tokens.refresh_token);
    return tokens;
  }

  // add/update the Hash Refresh Token in the user object
  async updateHashRT(userId: number, refreshToken: string): Promise<void> {
    // hashing the Refresh Token
    const hash = await argon.hash(refreshToken);

    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashRT: hash,
      },
    });
  }

  // JWT signing function
  async signTokens(userId: number, userEmail: string): Promise<jwtPayload> {
    const payload = { sub: userId, email: userEmail };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwt.signAsync(payload, {
        expiresIn: '15m',
        secret: this.config.get<string>('JWT_AT_SECRET'),
      }),
      this.jwt.signAsync(payload, {
        expiresIn: '7d',
        secret: this.config.get<string>('JWT_RT_SECRET'),
      }),
    ]);

    return { access_token: accessToken, refresh_token: refreshToken };
  }
}
