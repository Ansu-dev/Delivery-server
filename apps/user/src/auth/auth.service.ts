import { BadRequestException, Injectable } from '@nestjs/common';
import { RegisterDto } from './dto/register-dto';
import { UserService } from '../user/user.service';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from '../user/entity/user.entity';
import { Repository } from 'typeorm';
import bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  register(rawToken: string, dto: RegisterDto) {
    const { email, password } = this.parseBasicToken(rawToken);

    return this.userService.create({
      ...dto,
      email,
      password,
    });
  }

  parseBasicToken(rawToken: string) {
    const basicSplit = rawToken.split(' ');

    if (basicSplit.length !== 2) {
      throw new BadRequestException('token invalid');
    }

    const [basic, token] = basicSplit;

    if (basic.toLowerCase() !== 'basic') {
      throw new BadRequestException('token invalid');
    }

    const decoded = Buffer.from(token, 'base64').toString('utf-8');

    const tokenSplit = decoded.split(':');

    if (tokenSplit.length !== 2) {
      throw new BadRequestException('token invalid');
    }

    const [email, password] = tokenSplit;

    return { email, password };
  }

  async login(rawToken: string) {
    const { email, password } = this.parseBasicToken(rawToken);

    const user = await this.authenticate(email, password);

    return {
      refreshToken: await this.issueToken(user, true),
      accessToken: await this.issueToken(user, false),
    };
  }

  async authenticate(email: string, password: string) {
    const user = await this.userRepository.findOne({
      where: {
        email,
      },
      select: {
        id: true,
        email: true,
        password: true,
      },
    });
    if (!user) {
      throw new BadRequestException('Invalid credentials');
    }

    const passOk = await bcrypt.compare(password, user.password);
    if (!passOk) {
      throw new BadRequestException('Invalid credentials');
    }

    return user;
  }

  async issueToken(user: any, isRefreshToken: boolean) {
    const refreshTokenSeceret = this.configService.getOrThrow<string>('REFRESH_TOKEN_SECRET');
    const accessTokenSeceret = this.configService.getOrThrow<string>('ACCESS_TOKEN_SECRET');

    return this.jwtService.signAsync(
      {
        sub: user.id ?? user.sub,
        role: user.role,
        type: isRefreshToken ? 'refresh' : 'access',
      },
      {
        secret: isRefreshToken ? refreshTokenSeceret : accessTokenSeceret,
        expiresIn: '3600h',
      },
    );
  }
}
