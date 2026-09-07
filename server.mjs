import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config({
  path: path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    ".env"
  )
});

import express from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { GoogleGenAI } from "@google/genai";

const app = express();
const PORT = 3000;

// --------------------------------------------------
// BASIC SECURITY
// --------------------------------------------------

app.disable("x-powered-by");

app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "http://127.0.0.1:3000",
      "https://krishna692006.github.io",
      "null"
    ],
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type"]
  })
);

app.use(express.json({ limit: "50kb" }));

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many requests. Please wait a moment and try again."
  }
});

// --------------------------------------------------
// API KEY
// --------------------------------------------------

const apiKey = process.env.GEMINI_API_KEY;

if (!apiKey) {
  console.error("GEMINI_API_KEY is not configured.");
  process.exit(1);
}

const ai = new GoogleGenAI({
  apiKey
});

// --------------------------------------------------
// PLANT DATA
// --------------------------------------------------

const trustedPlantData = `
You are PlantChat for Herbal Plant Explorer.

The website contains structured information about medicinal and
herbal plants, their botanical names, plant parts, active compounds,
traditional uses and formulations.

IMPORTANT:
1. Prefer the trusted Herbal Plant Explorer data whenever it contains
   the answer.
2. If the trusted data does not contain enough information, use Google
   Search grounding to obtain current/relevant information.
3. Never pretend that web information came from the Herbal Plant
   Explorer database.
4. Clearly distinguish website information from additional web information
   when useful.
5. Understand the user's language and answer in the same language.
6. Understand multilingual names, regional names, transliterations,
   botanical names and common names.
7. Maintain conversational context when conversation history is provided.
8. Speak naturally and helpfully, like a friendly knowledgeable assistant.
9. Do not invent plant names, medicinal claims, compounds or formulations.
10. For medical symptoms, diagnosis, treatment, medicine selection or dose,
    do not diagnose or prescribe. Give a clear safety warning and advise
    consulting a qualified doctor/AYUSH practitioner.

SAFETY WARNING:
If the user asks for medicine, treatment, dosage, or advice for symptoms,
include a clearly visible warning in the user's language AND English.

English warning:
"⚠️ Medical Safety Warning: This information is for educational purposes
only. Do not start, stop, or change any medicine or treatment based only
on this chat. Please consult a qualified doctor or AYUSH practitioner.
Herbal medicines can also have side effects and interactions."

Do not claim that Herbal Plant Explorer is responsible for a person's
medical outcome. Encourage professional medical advice instead.
`;

// --------------------------------------------------
// HEALTH CHECK
// --------------------------------------------------

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "Herbal Plant Explorer AI"
  });
});

// --------------------------------------------------
// AI CHAT
// --------------------------------------------------

app.post("/api/chat", chatLimiter, async (req, res) => {
  try {
    const message = req.body?.message;

    if (typeof message !== "string" || message.trim().length === 0) {
      return res.status(400).json({
        error: "Message is required."
      });
    }

    if (message.length > 4000) {
      return res.status(400).json({
        error: "Message is too long."
      });
    }

    const prompt = `
${trustedPlantData}

USER MESSAGE:
${message.trim()}

Answer naturally and conversationally.
Detect the language automatically.
Reply in the same language/script used by the user whenever possible.
`;

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: prompt,
      config: {
        tools: [{ googleSearch: {} }]
      }
    });

    const answer =
      typeof response.text === "string" && response.text.trim()
        ? response.text.trim()
        : "Sorry, I could not generate a response.";

    return res.json({
      answer
    });

  } catch (error) {
    console.error("FULL ERROR:", error);

    return res.status(500).json({
      error: "The AI service is temporarily unavailable."
    });
  }
});

// --------------------------------------------------
// START SERVER
// --------------------------------------------------

app.listen(PORT, "127.0.0.1", () => {
  console.log(
    `Herbal Plant Explorer AI running on http://127.0.0.1:${PORT}`
  );
});