import { Body, Controller, Post, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register-dto';
import { Authorization } from './decorator/authorization.decorator';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  registerUser(@Authorization() token: string, @Body() registerDto: RegisterDto) {
    if (!token) {
      throw new UnauthorizedException('token not found');
    }

    return this.authService.register(token, registerDto);
  }
}
