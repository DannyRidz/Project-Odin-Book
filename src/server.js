import "dotenv/config";
import express from "express";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "../generated/prisma/client.js";

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  throw new Error("DATABASE_URL is missing");
}

const adapter = new PrismaPg({ connectionString: databaseUrl });
const prisma = new PrismaClient({ adapter });
const app = express();

app.get("/", async (_request, response) => {
  const userCount = await prisma.user.count();
  response.send(`Odin Book is ready. Users: ${userCount}`);
});

const port = Number(process.env.PORT ?? 3000);

app.listen(port, () => {
  console.log(`Odin Book is running at http://localhost:${port}`);
});
