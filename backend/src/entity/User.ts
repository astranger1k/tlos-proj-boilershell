import { Entity, PrimaryGeneratedColumn, Column } from "typeorm"

@Entity()
export class User {
    @PrimaryGeneratedColumn()
    id!: number

    @Column()
    firstName!: string

    @Column()
    lastName!: string

    @Column()
    isActive!: boolean

    @Column()
    email!: string

    @Column()
    password!: string

    @Column()
    role!: string

    @Column()
    createdAt!: Date

    @Column()
    updatedAt!: Date

    // Profile picture ()
}