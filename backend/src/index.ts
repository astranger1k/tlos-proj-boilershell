import "reflect-metadata";

import express, { Express, Request, Response } from "express";
import passport from "passport";
import session from "express-session";
import dotenv from "dotenv";

// Import the authRouter
import { authRouter } from "@router/auth";

dotenv.config();

const app: Express = express();
const port = process.env.PORT || 3000;

app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: true }
}));

app.get("/", (req: Request, res: Response) => {
  res.send("Express + TypeScript Server");
});

// Auth router
app.use("/auth", authRouter);

app.listen(port, () => {
  console.log(`[server]: Server is running at http://localhost:${port}`);
});