
import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
    constructor(private prisma: PrismaService){}
    async createUser(data: CreateUserDto){
        const existingUser = await this.prisma.users.findUnique({ // check the already have an account or not. 
            where: {email : data.email}  // Check if a user already exists in the database by matching the email
        })
        if(existingUser){
            throw new BadRequestException('User with this email already exists.'); // if a user already exist then it will throw the request. 
        }
        const encyptedPassword = await bcrypt.hash(data.password, 10); // encrypted the password for extra security. 
        const save = await this.prisma.users.create({       // here is prisma.user means call the user collection from the schema.prisma.  
            data : {
                name : data.name,
                email: data.email,
                password: encyptedPassword

            }
        })
        return {message:"Registration successfull"}
    }
}
