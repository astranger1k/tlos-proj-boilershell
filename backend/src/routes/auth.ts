// Express, passport, passport-local, crypto, user
import express, { Express, Request, Response } from "express";
import dotenv from "dotenv";
import passport from "passport";
import passportLocal from "passport-local";
import argon2 from "argon2";
import { User } from "@entity/User";
import { AppDataSource } from "@service/data-source";

dotenv.config();

// Create and export the authRouter
export const authRouter = express.Router();

authRouter.use(express.json());

// User repository
const userRepository = AppDataSource.getRepository(User);

// Passport local strategy
passport.use(new passportLocal.Strategy(
    function (username, password, done) {
        userRepository.findOneBy({ email: username })
            .then((user) => {
                if (!user) {
                    return done(null, false, { message: "Incorrect username." });
                }
                argon2.verify(user.password, password)
                    .then((match) => {
                        if (match) {
                            return done(null, user);
                        }
                        return done(null, false, { message: "Incorrect password." });
                    });
            })
            .catch((err) => {
                return done(err);
            });
    }
));

// Passport serialization
passport.serializeUser(function (user: any, done) {
    // Serialize the user id
    done(null, user.id);
});

passport.deserializeUser(function (id: number, done) {
    userRepository.findOneBy({ id })
        .then((user) => {
            done(null, user);
        })
        .catch((err) => {
            done(err);
        });
});

// Login endpoint
authRouter.post("/login", passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    // failureFlash: true
}), (req: Request, res: Response) => {
    res.send("Logged in");
});

// Register endpoint
authRouter.post("/register", async (req: Request, res: Response) => {
    let { username, password } = req.body;

    if (!username || !password) {
        res.status(400).json({ message: "Username and password are required" });
    } else if (await userRepository.findOneBy({ email: username })) {
        res.status(400).json({ message: "User already exists" });
    } else if (password.length < 8) {
        res.status(400).json({ message: "Password must be at least 8 characters" });
    } else {
        try {
            const hash = await argon2.hash(password);
            const user = await userRepository.save({
                email: username,
                password: hash,
                role: "user",
                createdAt: new Date(),
                updatedAt: new Date()
            });
            res.json(user);
        } catch (err) {
            res.status(500).json({ message: "Internal server error" });
        }
    }
});