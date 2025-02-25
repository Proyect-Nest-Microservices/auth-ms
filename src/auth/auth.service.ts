import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { LoginUserDto, RegisterUserDto } from './dto';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt'
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit{

    private readonly logger = new Logger('Auth-Service');

    constructor(
        private readonly jwtService: JwtService
    ) {
        super();
    }
    onModuleInit() {
        this.$connect();
        this.logger.log('MongoDb connected')
    }

    async signJwt(payload:JwtPayload) {
        return this.jwtService.sign(payload)
    }

    async verifyToken(token: string) {
        try {
            const {sub,iat, exp, ...user} = this.jwtService.verify(token, {
                secret:envs.JWT_SECRET
            })
            return {
                user,
                token: await this.signJwt(user)
            }
        } catch (error) {
            throw new RpcException({
                status: 401,
                message: 'Invalid Token'
            })
        }
    }

    async registerUser(registerUserDto: RegisterUserDto) {
        const {name,email,password} = registerUserDto
        try {
            const user = await this.user.findUnique({
                where:{email}
            })
            if (user) {
                throw new RpcException({
                    status: HttpStatus.BAD_REQUEST,
                    message:'User already exists'
                })
            }
            const newUser = await this.user.create({
                data: {
                    email,
                    name,
                    password: bcrypt.hashSync(password,10)
                }
            })

            const {password:_, ...rest } = newUser;

            return {
                user: rest,
                token: await this.signJwt(rest)
            }
            
        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            })
        }
        
    }

    async loginUser(loginUserDto: LoginUserDto) {
        const {email,password} = loginUserDto
        try {
            const user = await this.user.findUnique({
                where:{email}
            })
            if (!user) {
                throw new RpcException({
                    status: HttpStatus.BAD_REQUEST,
                    message:'User/Password not valid'
                })
            }
            
            const isPasswordValid = bcrypt.compareSync(password, user.password)
            if (!isPasswordValid) {
                throw new RpcException({
                    status: HttpStatus.BAD_REQUEST,
                    message:'User/Password not valid'
                })
            }

            const {password:_, ...rest } = user;

            return {
                user: rest,
                token: await this.signJwt(rest)
            }
            
        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            })
        }
        
    }

}
