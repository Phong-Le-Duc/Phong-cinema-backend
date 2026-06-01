import { prisma } from './lib/prisma'
import cors from "cors";
import express from "express";
import bcrypt from "bcryptjs";

const app = express()

const allowedOrigins = (process.env.CORS_ORIGINS || "http://localhost:5173")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);

app.use(cors({
    origin: allowedOrigins,
    credentials: true
}));
app.use(express.json())

// Register endpoint
app.post("/register", async (req, res) => {
    const { email, password, name } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: "Email and password required" });
    }
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
        return res.status(409).json({ message: "User already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
        data: {
            email,
            name,
            password: hashedPassword
        }
    });
    res.status(201).json({ id: user.id, email: user.email, name: user.name });
});

// Login endpoint
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: "Email and password required" });
    }
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !user.password) {
        return res.status(401).json({ message: "Invalid credentials" });
    }
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
        return res.status(401).json({ message: "Invalid credentials" });
    }
    res.json({ id: user.id, email: user.email, name: user.name });
});

const port = Number(process.env.PORT || 4000);

app.listen(port, function () {
    console.log(`listening for request on port ${port}`);
})



// ---------------DELETE USER ----------------------------------------
app.delete("/user/:email", async function (req, res) {
    const email = req.params.email;
    // console.log(email);

    if (!email) {
        return res.status(400).json({ error: "Email required" });
    }

    const user = await prisma.user.findUnique({
        where: { email }
    });

    if (!user) {
        return res.status(404).json({ error: "User not found!" });
    }


    await prisma.user.delete({
        where: { email }
    });

    return res.status(200).json({ message: "Account deleted successfully" });
});