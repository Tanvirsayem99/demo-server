import { AuthService } from './auth.service';
import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Put,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { ChangePasswordDto } from './dto/updatePassword.dto';

@Controller('auth')
export class AuthController {
  constructor(private authservice: AuthService) {}
  @Post('login')
  login(
    @Body() data: { email: string; password: string },
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.authservice.login(data.email, data.password, response);
  }
  @Get('me') // this route will provide login data after authentication. the authentication token will send from front-end. 
  getMe(@Req() req: Request) {
    const token = req.cookies?.token;
    if (!token) throw new UnauthorizedException();
    try {
      const user = this.authservice.verifyToken(token); // verify the jwt token. 
      return user; //return the user email and name for access from front-end. 
    } catch {
      throw new UnauthorizedException();
    }
  }
  @Put('password')
  async updatePassword(@Req() req: Request, @Body() dto: ChangePasswordDto) {
    const token = req.cookies?.token; //get jwt token 
    if (!token) throw new UnauthorizedException();
    const user: any = await this.authservice.verifyToken(token); // verify the jwt token. 
    const userEmail = user.payload.email; //get email from jwt authentication. 
    return this.authservice.updateUserData(userEmail, dto);
  }
}
