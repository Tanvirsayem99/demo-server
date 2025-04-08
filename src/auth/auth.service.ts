import { JwtService } from '@nestjs/jwt';
import { PrismaService } from './../prisma/prisma.service';
import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { LoginDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt';
import { Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
  ) {}
  async login(
    email: LoginDto['email'],
    password: LoginDto['password'],
    res: Response,
  ) {
    const user = await this.prisma.users.findUnique({
      // check if user exist or not.
      where: {
        email: email,
      },
    });
    if (!user) {
      throw new BadRequestException('user data invalid'); // when user don't have account it will return "user data invalid".
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) throw new BadRequestException('password invalid'); // when password did not match then it will return "password invalid"
    const payload = {
      name: user.name,
      email: user.email, // payload will save name and email, it will help us to get the user data fromo front end when we send a request from front-end with authentication using http cookies.
    };
    const token = this.jwt.sign({ payload });
    res.cookie('token', token, {
      // send jwt token through cookie.
      secure: true,
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60, // expire time
    });

    return { token };
  }
  async verifyToken(token: string) {
    try {
      return this.jwt.verify(token); // verify the token. this function imported from jwt.middleware.ts where verification procces excuted.
    } catch {
      throw new UnauthorizedException('Invalid token');
    }
  }

  async updateUserData(userEmail: string, data: any) {
    //here find the user where we can update the password
    const user: any = await this.prisma.users.findUnique({
      where: {
        email: userEmail,
      },
      select: {
        id: true,
        password: true, // must include this
      },
    });
    //check if the user exist or not
    if (!user) throw new UnauthorizedException('User not found');
    // check existing password correct or incorrect
    const isMatch = await bcrypt.compare(data.currentPassword, user.password);
    if (!isMatch)
      throw new UnauthorizedException('Current password is incorrect');
    // encrypted the new password
    const hashedNewPassword = await bcrypt.hash(data.newPassword, 10);
    // update password where provided email matched. 
    await this.prisma.users.update({
      where: { email: userEmail },
      data: { password: hashedNewPassword },
    });

    return { message: 'Password updated successfully' };
  }
}
