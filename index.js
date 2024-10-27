require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const helmet = require("helmet");
const upload = require("./multer");

const { authenticateToken } = require("./utilities");
const User = require("./models/user.model");
const TravelStory = require("./models/travelStory.model");

const app = express();

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URL)
  .then(() => {
    console.log("Connected to MongoDB!");
  })
  .catch((err) => {
    console.log(err);
  });

// Middleware
app.use(express.json());
app.use(cors({ origin: "*" }));

// Apply security headers conditionally
if (process.env.NODE_ENV === "development") {
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "https://vercel.live"],
          objectSrc: ["'none'"],
        },
      },
    })
  );
} else {
  app.use(helmet());
}

// Routes

// Create Account
app.post("/create-account", async (req, res) => {
  const { fullName, email, password } = req.body;
  if (!fullName || !email || !password) {
    return res.status(400).json({ error: true, message: "All fields are required" });
  }

  const isUser = await User.findOne({ email });
  if (isUser) {
    return res.status(400).json({ error: true, message: "User already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ fullName, email, password: hashedPassword });
  await user.save();

  const accessToken = jwt.sign({ userId: user._id }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "72h" });
  return res.status(201).json({ error: false, user: { fullName: user.fullName, email: user.email }, accessToken, message: "Registration Successful" });
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Email and Password are required" });
  }

  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ message: "Invalid Credentials" });
  }

  const accessToken = jwt.sign({ userId: user._id }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "72h" });
  return res.json({ error: false, message: "Login Successful", user: { fullName: user.fullName, email: user.email }, accessToken });
});

// Get User
app.get("/get-user", authenticateToken, async (req, res) => {
  const { userId } = req.user;
  const isUser = await User.findById(userId);
  if (!isUser) return res.sendStatus(401);
  return res.json({ user: isUser });
});

// Image Upload
app.post("/image-upload", upload.single("image"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: true, message: "No image uploaded" });
  const imageUrl = `http://localhost:8000/uploads/${req.file.filename}`;
  res.status(200).json({ imageUrl });
});

// Delete Image
app.delete("/delete-image", async (req, res) => {
  const { imageUrl } = req.query;
  if (!imageUrl) return res.status(400).json({ error: true, message: "imageUrl parameter is required" });

  const filename = path.basename(imageUrl);
  const filePath = path.join(__dirname, "uploads", filename);

  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
    res.status(200).json({ message: "Image deleted successfully" });
  } else {
    res.status(200).json({ error: true, message: "Image not found" });
  }
});

// Serve static files
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use("/assets", express.static(path.join(__dirname, "assets")));

// Add Travel Story
app.post("/add-travel-story", authenticateToken, async (req, res) => {
  const { title, story, visitedLocation, imageUrl, visitedDate } = req.body;
  const { userId } = req.user;

  if (!title || !story || !visitedLocation || !imageUrl || !visitedDate) {
    return res.status(400).json({ error: true, message: "All fields are required" });
  }

  const parsedVisitedDate = new Date(parseInt(visitedDate));
  try {
    const travelStory = new TravelStory({ title, story, visitedLocation, userId, imageUrl, visitedDate: parsedVisitedDate });
    await travelStory.save();
    res.status(201).json({ story: travelStory, message: "Added Successfully" });
  } catch (error) {
    res.status(400).json({ error: true, message: error.message });
  }
});

// Other routes (edit, delete story, etc.) go here...

// Start Server
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`Backend is running on port ${PORT}`);
});

module.exports = app;
