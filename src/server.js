import "dotenv/config";
import express from "express";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import bcrypt from "bcryptjs";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "../generated/prisma/client.js";

const databaseUrl = process.env.DATABASE_URL;
const sessionSecret = process.env.SESSION_SECRET;

if (!databaseUrl || !sessionSecret) {
  throw new Error("DATABASE_URL and SESSION_SECRET are required");
}

const adapter = new PrismaPg({ connectionString: databaseUrl });
const prisma = new PrismaClient({ adapter });
const PgStore = connectPgSimple(session);
const app = express();

app.set("view engine", "ejs");

if (process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1);
}

app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    store: new PgStore({
      conString: databaseUrl,
      createTableIfMissing: true,
    }),
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    },
  }),
);

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await prisma.user.findUnique({
        where: { username: username.toLowerCase() },
      });

      if (!user) {
        return done(null, false);
      }

      const passwordMatches = await bcrypt.compare(password, user.passwordHash);

      if (!passwordMatches) {
        return done(null, false);
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }),
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await prisma.user.findUnique({ where: { id } });
    done(null, user || false);
  } catch (error) {
    done(error);
  }
});

app.use(passport.initialize());
app.use(passport.session());

app.get("/", async (request, response) => {
  const userCount = await prisma.user.count();
  response.render("home", { user: request.user, userCount });
});

app.get("/sign-up", (_request, response) => {
  response.render("signup", { error: null });
});

app.post("/sign-up", async (request, response, next) => {
  const username =
    typeof request.body.username === "string"
      ? request.body.username.trim().toLowerCase()
      : "";
  const displayName =
    typeof request.body.displayName === "string"
      ? request.body.displayName.trim()
      : "";
  const password =
    typeof request.body.password === "string" ? request.body.password : "";

  if (
    !/^[a-z0-9_]{3,20}$/.test(username) ||
    displayName.length < 1 ||
    displayName.length > 50 ||
    password.length < 8
  ) {
    return response.status(400).render("signup", {
      error:
        "Use a 3–20 character username, a display name, and a password of at least 8 characters.",
    });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await prisma.user.create({
      data: { username, displayName, passwordHash },
    });

    request.logIn(user, (error) => {
      if (error) return next(error);
      response.redirect("/");
    });
  } catch (error) {
    if (error.code === "P2002") {
      return response.status(400).render("signup", {
        error: "That username is already taken.",
      });
    }

    next(error);
  }
});

app.get("/log-in", (request, response) => {
  response.render("login", { error: request.query.error === "1" });
});

app.post(
  "/log-in",
  passport.authenticate("local", {
    failureRedirect: "/log-in?error=1",
  }),
  (_request, response) => {
    response.redirect("/");
  },
);

app.post("/log-out", (request, response, next) => {
  request.logOut((error) => {
    if (error) return next(error);

    request.session.destroy((error) => {
      if (error) return next(error);
      response.clearCookie("connect.sid");
      response.redirect("/log-in");
    });
  });
});

app.use((error, _request, response, _next) => {
  console.error(error);
  response.status(500).send("Something went wrong.");
});

const port = Number(process.env.PORT ?? 3000);

app.listen(port, () => {
  console.log(`Odin Book is running at http://localhost:${port}`);
});
