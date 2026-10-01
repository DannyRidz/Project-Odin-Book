import "dotenv/config";
import express from "express";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import bcrypt from "bcryptjs";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "../generated/prisma/client.js";
import { randomBytes } from "node:crypto";

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

const publicPaths = new Set(["/log-in", "/sign-up", "/guest"]);

app.use((request, response, next) => {
  if (publicPaths.has(request.path)) {
    return next();
  }

  if (request.isAuthenticated()) {
    return next();
  }

  response.redirect("/log-in");
});

app.use((request, response, next) => {
  if (!request.user?.isGuest) return next();

  if (
    request.method === "POST" &&
    !["/log-out", "/log-in", "/sign-up"].includes(request.path)
  ) {
    return response.status(403).send("Guest preview is read-only.");
  }

  if (
    request.method === "GET" &&
    ["/connections", "/posts", "/profile/setup"].includes(request.path)
  ) {
    return response.redirect("/explore");
  }

  next();
});

app.use(express.static("public"));

app.get("/", async (request, response) => {
  const follows = await prisma.follow.findMany({
    where: {
      followerId: request.user.id,
      status: "ACCEPTED",
    },
    select: { followingId: true },
  });

  const authorIds = [
    request.user.id,
    ...follows.map((follow) => follow.followingId),
  ];

  const posts = await prisma.post.findMany({
    where: { authorId: { in: authorIds } },
    orderBy: { createdAt: "desc" },
    take: 50,
    include: postIncludes(request.user.id),
  });

  response.render("home", { user: request.user, posts });
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

app.post("/guest", async (request, response, next) => {
  try {
    const guest = await prisma.user.upsert({
      where: { username: "guest-preview" },
      update: {},
      create: {
        username: "guest-preview",
        displayName: "Guest",
        passwordHash: await bcrypt.hash(randomBytes(32).toString("hex"), 12),
        isGuest: true,
      },
    });

    request.logIn(guest, (error) => {
      if (error) return next(error);
      response.redirect("/explore");
    });
  } catch (error) {
    next(error);
  }
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

app.get("/connections", async (request, response) => {
  const userId = request.user.id;

  const [following, incoming, outgoing] = await Promise.all([
    prisma.follow.findMany({
      where: { followerId: userId, status: "ACCEPTED" },
      include: { following: true },
      orderBy: { createdAt: "desc" },
    }),
    prisma.follow.findMany({
      where: { followingId: userId, status: "PENDING" },
      include: { follower: true },
      orderBy: { createdAt: "desc" },
    }),
    prisma.follow.findMany({
      where: { followerId: userId, status: "PENDING" },
      include: { following: true },
      orderBy: { createdAt: "desc" },
    }),
  ]);

  response.render("connections", { following, incoming, outgoing });
});

app.post("/connections/request", async (request, response) => {
  const username =
    typeof request.body.username === "string"
      ? request.body.username.trim().toLowerCase()
      : "";

  const target = await prisma.user.findUnique({ where: { username } });

  if (!target || target.id === request.user.id) {
    return response.status(400).send("Choose another existing user.");
  }

  try {
    await prisma.follow.create({
      data: {
        followerId: request.user.id,
        followingId: target.id,
      },
    });
  } catch (error) {
    if (error.code !== "P2002") throw error;
  }

  response.redirect(
    request.body.returnTo === "/users" ? "/users" : "/connections",
  );
});

app.post("/connections/:id/accept", async (request, response) => {
  const id = Number(request.params.id);

  if (!Number.isSafeInteger(id) || id < 1) {
    return response.sendStatus(404);
  }

  const result = await prisma.follow.updateMany({
    where: {
      id,
      followingId: request.user.id,
      status: "PENDING",
    },
    data: { status: "ACCEPTED" },
  });

  if (result.count === 0) return response.sendStatus(404);
  response.redirect("/connections");
});

app.post("/connections/:id/decline", async (request, response) => {
  const id = Number(request.params.id);

  if (!Number.isSafeInteger(id) || id < 1) {
    return response.sendStatus(404);
  }

  const result = await prisma.follow.deleteMany({
    where: {
      id,
      followingId: request.user.id,
      status: "PENDING",
    },
  });

  if (result.count === 0) return response.sendStatus(404);
  response.redirect("/connections");
});

app.post("/connections/:id/cancel", async (request, response) => {
  const id = Number(request.params.id);

  if (!Number.isSafeInteger(id) || id < 1) {
    return response.sendStatus(404);
  }

  const result = await prisma.follow.deleteMany({
    where: {
      id,
      followerId: request.user.id,
      status: "PENDING",
    },
  });

  if (result.count === 0) return response.sendStatus(404);
  response.redirect("/connections");
});

app.post("/connections/:id/unfollow", async (request, response) => {
  const id = Number(request.params.id);

  if (!Number.isSafeInteger(id) || id < 1) {
    return response.sendStatus(404);
  }

  const result = await prisma.follow.deleteMany({
    where: {
      id,
      followerId: request.user.id,
      status: "ACCEPTED",
    },
  });

  if (result.count === 0) return response.sendStatus(404);
  response.redirect("/connections");
});

function postIncludes(userId) {
  return {
    author: {
      select: { username: true, displayName: true },
    },
    comments: {
      orderBy: { createdAt: "asc" },
      include: {
        author: {
          select: { username: true, displayName: true },
        },
      },
    },
    likes: {
      where: { userId },
      select: { id: true },
    },
    _count: {
      select: { likes: true, comments: true },
    },
  };
}

function postReturnPath(request) {
  return request.body.returnTo === "/" ? "/" : "/explore";
}

app.get("/posts", async (request, response) => {
  const posts = await prisma.post.findMany({
    where: { authorId: request.user.id },
    orderBy: { createdAt: "desc" },
    take: 50,
    include: postIncludes(request.user.id),
  });

  response.render("posts", { posts, error: null });
});

app.post("/posts", async (request, response) => {
  const content =
    typeof request.body.content === "string" ? request.body.content.trim() : "";
  const imageInput =
    typeof request.body.imageUrl === "string"
      ? request.body.imageUrl.trim()
      : "";

  let imageUrl = null;
  let imageIsValid = true;

  if (imageInput) {
    try {
      const parsedUrl = new URL(imageInput);
      imageIsValid =
        ["http:", "https:"].includes(parsedUrl.protocol) &&
        imageInput.length <= 2048;

      if (imageIsValid) imageUrl = parsedUrl.href;
    } catch {
      imageIsValid = false;
    }
  }

  if (content.length < 1 || content.length > 500 || !imageIsValid) {
    const posts = await prisma.post.findMany({
      where: { authorId: request.user.id },
      orderBy: { createdAt: "desc" },
      take: 50,
      include: postIncludes(request.user.id),
    });

    return response.status(400).render("posts", {
      posts,
      error: !imageIsValid
        ? "Enter an image URL beginning with http:// or https://."
        : "Write a post between 1 and 500 characters.",
    });
  }

  await prisma.post.create({
    data: {
      authorId: request.user.id,
      content,
      imageUrl,
    },
  });

  response.redirect("/posts");
});

app.get("/explore", async (request, response) => {
  const posts = await prisma.post.findMany({
    orderBy: { createdAt: "desc" },
    take: 50,
    include: postIncludes(request.user.id),
  });

  response.render("explore", { posts, isGuest: request.user.isGuest });
});

app.post("/posts/:id/like", async (request, response) => {
  const postId = Number(request.params.id);

  if (!Number.isSafeInteger(postId) || postId < 1) {
    return response.sendStatus(404);
  }

  const post = await prisma.post.findUnique({
    where: { id: postId },
    select: { id: true },
  });

  if (!post) return response.sendStatus(404);

  try {
    await prisma.like.create({
      data: {
        userId: request.user.id,
        postId,
      },
    });
  } catch (error) {
    if (error.code !== "P2002") throw error;
  }

  response.redirect(postReturnPath(request));
});

app.post("/posts/:id/unlike", async (request, response) => {
  const postId = Number(request.params.id);

  if (!Number.isSafeInteger(postId) || postId < 1) {
    return response.sendStatus(404);
  }

  await prisma.like.deleteMany({
    where: {
      userId: request.user.id,
      postId,
    },
  });

  response.redirect(postReturnPath(request));
});

app.post("/posts/:id/comments", async (request, response) => {
  const postId = Number(request.params.id);
  const content =
    typeof request.body.content === "string" ? request.body.content.trim() : "";

  if (!Number.isSafeInteger(postId) || postId < 1) {
    return response.sendStatus(404);
  }

  if (content.length < 1 || content.length > 500) {
    return response
      .status(400)
      .send("Write a comment between 1 and 500 characters.");
  }

  const post = await prisma.post.findUnique({
    where: { id: postId },
    select: { id: true },
  });

  if (!post) return response.sendStatus(404);

  await prisma.comment.create({
    data: {
      postId,
      authorId: request.user.id,
      content,
    },
  });

  response.redirect(postReturnPath(request));
});

app.get("/profile/setup", (request, response) => {
  response.render("profile-setup", {
    user: request.user,
    error: null,
  });
});

app.post("/profile/setup", async (request, response) => {
  const displayName =
    typeof request.body.displayName === "string"
      ? request.body.displayName.trim()
      : "";
  const bio =
    typeof request.body.bio === "string" ? request.body.bio.trim() : "";
  const pictureInput =
    typeof request.body.photoUrl === "string"
      ? request.body.photoUrl.trim()
      : "";

  if (displayName.length < 1 || displayName.length > 50 || bio.length > 160) {
    return response.status(400).render("profile-setup", {
      user: request.user,
      error:
        "Use a display name up to 50 characters and a bio up to 160 characters.",
    });
  }

  const data = { displayName, bio };

  if (pictureInput) {
    try {
      const pictureUrl = new URL(pictureInput);

      if (pictureUrl.protocol !== "https:" || pictureInput.length > 2048) {
        throw new Error("Invalid picture URL");
      }

      data.photoUrl = pictureUrl.href;
    } catch {
      return response.status(400).render("profile-setup", {
        user: request.user,
        error: "Use a valid HTTPS URL for your picture.",
      });
    }
  }

  await prisma.user.update({
    where: { id: request.user.id },
    data,
  });

  response.redirect("/profile/setup");
});

app.get("/users", async (request, response) => {
  const [users, follows] = await Promise.all([
    prisma.user.findMany({
      where: { isGuest: false },
      select: {
        id: true,
        username: true,
        displayName: true,
        bio: true,
        photoUrl: true,
      },
      orderBy: { username: "asc" },
    }),
    prisma.follow.findMany({
      where: { followerId: request.user.id },
      select: { followingId: true, status: true },
    }),
  ]);

  const followByUserId = new Map(
    follows.map((follow) => [follow.followingId, follow.status]),
  );

  response.render("users", {
    users,
    currentUserId: request.user.id,
    followByUserId,
    isGuest: request.user.isGuest,
  });
});

app.get("/users/:username", async (request, response) => {
  const username = request.params.username.toLowerCase();

  const profileUser = await prisma.user.findUnique({
    where: { username },
    select: {
      id: true,
      username: true,
      displayName: true,
      bio: true,
      photoUrl: true,
    },
  });

  if (!profileUser) {
    return response.sendStatus(404);
  }

  const posts = await prisma.post.findMany({
    where: { authorId: profileUser.id },
    orderBy: { createdAt: "desc" },
    take: 50,
    include: postIncludes(request.user.id),
  });

  response.render("profile", {
    profileUser,
    posts,
    isOwnProfile: profileUser.id === request.user.id,
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
