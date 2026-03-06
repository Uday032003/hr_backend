require("dotenv").config();

const dns = require("dns").promises;
const { Resolver } = require("dns").promises;
const postgres = require("postgres");
const express = require("express");
const cors = require("cors");
const nodemailer = require("nodemailer");
const { Server } = require("socket.io");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { v4 } = require("uuid");
const cron = require("node-cron");
const { Parser } = require("json2csv");
const multer = require("multer");
const csv = require("csv-parser");
const fs = require("fs");
const UAParser = require("ua-parser-js");

const upload = multer({ dest: "uploads/" });

const app = express();
const resolver = new Resolver();
app.use(express.json());
app.use(cors());
app.set("trust proxy", true);
resolver.setServers(["8.8.8.8"]);

const PORT = process.env.PORT || 3001;

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server is running on port ${PORT}`);
});

const sendTelegramMessage = async (message) => {
  try {
    const token = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;
    if (!token || !chatId) return;
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        chat_id: chatId,
        text: message,
        parse_mode: "HTML",
      }),
    });
  } catch (error) {
    console.error("Telegram error:", error.message);
  }
};

const getWorkingDuration = (login, logout, breakOut, breakIn, nowTime) => {
  const startDate = new Date(login);
  const endDate = logout ? new Date(logout) : nowTime;

  let diffMs = (endDate - startDate) / 1000;

  if (breakOut && !breakIn) {
    const breakOutDate = new Date(breakOut);
    diffMs -= (endDate - breakOutDate) / 1000;
  }

  if (breakOut && breakIn) {
    const breakOutDate = new Date(breakOut);
    const breakInDate = new Date(breakIn);
    diffMs -= (breakInDate - breakOutDate) / 1000;
  }

  diffMs = Math.max(diffMs, 0);

  const hours = Math.floor(diffMs / 3600);
  const minutes = Math.floor((diffMs % 3600) / 60);
  const seconds = Math.floor(diffMs % 60);

  return `${hours}h ${minutes}m ${seconds}s`;
};

cron.schedule("0 0 * * *", async () => {
  try {
    const today = new Date().toISOString();
    await sql`
      UPDATE users
      SET selected_date = (${today} AT TIME ZONE 'Asia/Kolkata')
    `;
  } catch (error) {
    console.error("Error resetting selected_date:", error);
  }
});

const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

const connectionString = process.env.POSTGRE_CONNECTION_STRING;
const sql = postgres(connectionString, {
  ssl: "require",
});

(async () => {
  try {
    const result = await sql`SELECT NOW()`;
    console.log("✅ PostgreSQL connected at:", result[0].now);
  } catch (err) {
    console.error("❌ PostgreSQL connection failed:", err);
  }
})();

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

const sendVerificationEmail = async (email, link) => {
  const linkMailOptions = {
    from: `EcoAi Team ${process.env.SMTP_MAIL_FROM}`,
    to: email,
    subject: "Verify your email for EcoAi",
    html: `
      <p>Hello,</p>
      <p>Click the link below to verify your email and log in:</p>
      <p><a href="${link}">Verify my email</a></p>
      <p>This link will expire in 24 hours.</p>
    `,
  };
  try {
    await transporter.sendMail(linkMailOptions);
    return { success: true };
  } catch (error) {
    console.error("Error sending email:", error);

    if (error.response && error.response.includes("550 5.1.1")) {
      return { success: false, message: "Invalid email address" };
    }

    return {
      success: false,
      message: "Failed to send email. Please try again.",
    };
  }
};

const sendVerificationCode = async (email, code) => {
  const codeMailOptions = {
    from: `EcoAi Team ${process.env.SMTP_MAIL_FROM}`,
    to: email,
    subject: "Verification Code to reset your password",
    html: `
      <p>Hello,</p>
      <p>Your verification code: <strong>${code}</strong></p>
      <p>Use this code to reset your password. This code works for 10 minutes.</p>
    `,
  };
  try {
    await transporter.sendMail(codeMailOptions);
    return { success: true };
  } catch (error) {
    console.error("Error sending email:", error);

    if (error.response && error.response.includes("550 5.1.1")) {
      return { success: false, message: "Invalid email address" };
    }

    return {
      success: false,
      message: "Failed to send email. Please try again.",
    };
  }
};

const createVerificationToken = (userId) => {
  return jwt.sign(
    { userId },
    process.env.EMAIL_SECRET || "DEFAULT_EMAIL_SECRET",
    { expiresIn: "24h" },
  );
};

const createJwtToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET || "DEFAULT_JWT_SECRET");
};

const authMiddleware = (request, response, next) => {
  try {
    const authHeader = request.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return response
        .status(401)
        .json({ message: "Unauthorized: Token missing" });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "DEFAULT_JWT_SECRET",
    );

    request.userId = decoded.userId;

    next();
  } catch (error) {
    console.error("Auth Middleware Error:", error.message);
    return response.status(401).json({ message: "Invalid or expired token" });
  }
};

app.get("/", (req, res) => {
  res.send("EcoAI Backend is running 🚀");
});

// user create avuthunnadu
app.post("/signup", async (request, response) => {
  try {
    const { mail, password } = request.body;
    if (!mail || !password) {
      return response
        .status(400)
        .json({ message: "Email and password are required" });
    }

    const dbUser = await sql`
      SELECT * FROM users WHERE mail = ${mail}
    `;

    if (dbUser.length > 0) {
      return response.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUserId = v4();
    const userCreatedTime = new Date().toISOString();
    await sql`
      INSERT INTO users (id, mail, password, user_created_time)
      VALUES (${newUserId}, ${mail}, ${hashedPassword}, (${userCreatedTime} AT TIME ZONE 'Asia/Kolkata'))
    `;

    const createdUser = await sql`
      SELECT * FROM users WHERE mail = ${mail}
    `;

    if (createdUser.length === 0) {
      return response.status(500).json({ message: "Failed to create user" });
    }

    const verificationToken = createVerificationToken(newUserId);
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    await sql`
      UPDATE users
      SET verification_token = ${verificationToken},
          verification_expires = (${expiresAt}) AT TIME ZONE 'Asia/Kolkata'
      WHERE mail = ${mail}
    `;

    const verifyLink = `${
      process.env.BACKEND_URL || `http://localhost:${PORT}`
    }/verify/${encodeURIComponent(verificationToken)}`;

    const mailResult = await sendVerificationEmail(mail, verifyLink);

    if (!mailResult.success) {
      return response.status(500).json({
        message: mailResult.message || "Failed to send verification email",
      });
    }

    return response.status(200).json({
      message: "User created. Check your email for verification link.",
    });
  } catch (err) {
    console.error(err);
    return response.status(500).json({ message: "Server error" });
  }
});

// user verify avuthunnadu
app.get("/verify/:token", async (request, response) => {
  try {
    const { token } = request.params;

    if (!token) {
      return response
        .status(400)
        .json({ message: "Invalid verification link." });
    }

    const userResult = await sql`
      SELECT * FROM users WHERE verification_token = ${token}
    `;

    const user = userResult[0];

    if (!user) {
      return response
        .status(400)
        .json({ message: "Invalid or already used verification link." });
    }
    if (user.verification_expires) {
      const expiresAt = new Date(user.verification_expires);
      const now = new Date();

      if (expiresAt < now) {
        return response.status(400).json({
          message:
            "Verification link expired. Please request a new verification email.",
        });
      }
    }

    try {
      jwt.verify(token, process.env.EMAIL_SECRET || "DEFAULT_EMAIL_SECRET");
    } catch (err) {
      return response
        .status(400)
        .json({ message: "Invalid or expired token." });
    }

    await sql`
      UPDATE users 
      SET is_verified = true, verification_token = NULL, verification_expires = NULL
      WHERE mail = ${user.mail}
    `;

    const redirectUrl =
      process.env.FRONTEND_URL || "http://localhost:3000/verification";

    return response.redirect(302, redirectUrl);
  } catch (err) {
    console.error(err);
    return response
      .status(500)
      .json({ message: "Server error during verification." });
  }
});

// user login avuthunnadu
app.post("/login", async (request, response) => {
  try {
    const { mail, password } = request.body;

    if (!mail || !password) {
      return response
        .status(400)
        .json({ message: "Email and password required" });
    }

    const userResult = await sql`
      SELECT * FROM users WHERE mail = ${mail}
    `;

    const dbUser = userResult[0];

    if (!dbUser) {
      return response.status(400).json({ message: "Invalid user" });
    }

    if (!dbUser.is_verified) {
      return response
        .status(403)
        .json({ message: "Please verify your email before logging in" });
    }

    const isPasswordMatched = await bcrypt.compare(password, dbUser.password);
    if (!isPasswordMatched) {
      return response.status(400).json({ message: "Invalid password" });
    }

    const uid = dbUser.id;
    const jwtToken = createJwtToken(uid);

    return response.status(200).json({
      message: "Login successful",
      jwtToken,
      isUser: dbUser.isuser,
    });
  } catch (error) {
    console.error(error);
    return response.status(500).json({ message: "Server error" });
  }
});

// user resend verification email chesthunnadu
app.post("/resend-verification", async (request, response) => {
  try {
    const { mail } = request.body;

    if (!mail) {
      return response.status(400).json({ message: "Email required" });
    }

    const userResult = await sql`
      SELECT * FROM users WHERE mail = ${mail}
    `;

    const user = userResult[0];

    if (!user) {
      return response.status(400).json({ message: "User not found" });
    }

    if (user.isverified) {
      return response.status(200).json({ message: "Already verified" });
    }

    const verificationToken = createVerificationToken(user.id);
    const expiresAt = Date.now() + 24 * 60 * 60 * 1000;

    await sql`
      UPDATE users
      SET verification_token = ${verificationToken},
          verification_expires = ${expiresAt}
      WHERE mail = ${mail}
    `;

    const verifyLink = `${
      process.env.BACKEND_URL || `http://localhost:${PORT}`
    }/verify/${encodeURIComponent(verificationToken)}`;

    const mailResult = await sendVerificationEmail(mail, verifyLink);

    if (!mailResult.success) {
      return response.status(500).json({
        message: mailResult.message || "Failed to send verification email",
      });
    }

    return response.status(200).json({ message: "Verification email resent" });
  } catch (err) {
    console.error(err);
    return response.status(500).json({ message: "Server error" });
  }
});

// user location verify chesthunnadu
app.post("/verify-location", async (req, res) => {
  try {
    const adminResult = await sql`
      SELECT is_wifi_required 
      FROM users
      WHERE isuser=false
    `;
    const admin = adminResult[0];
    if (admin.is_wifi_required === "NO") {
      return res.status(200).json({
        success: true,
        message: "Wifi restriction is turned off by admin",
      });
    }
    const clientIP = req.body.detectedIP;
    const records = await resolver.resolve4("ecoai-attendance.duckdns.org");
    const officeIP = records[0];
    console.log(
      `[VERIFY] Received from Frontend: ${clientIP} | Office: ${officeIP}`,
    );

    if (clientIP === officeIP) {
      return res
        .status(200)
        .json({ success: true, message: "Location verified successfully" });
    }
    return res.status(403).json({
      success: false,
      message:
        "Access Denied: Please connect to the 'EcoAI' Wi-Fi to mark attendance.",
    });
  } catch (err) {
    return res.status(500).json({ message: "Verification error" });
  }
});

// user password reset chesthunnadu
app.post("/send-code", async (request, response) => {
  try {
    const { mail } = request.body;
    if (!mail) {
      return response.status(400).json({ message: "Email is required" });
    }
    const userResult = await sql`
      SELECT * FROM users WHERE mail = ${mail}
    `;
    const user = userResult[0];
    if (!user) {
      return response.status(400).json({ message: "User not found" });
    }
    const code = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    await sql`
      UPDATE users
      SET reset_code = ${code},
          reset_code_expires = (${expiresAt} AT TIME ZONE 'Asia/Kolkata')
      WHERE mail = ${mail}
    `;
    const mailResult = await sendVerificationCode(mail, code);
    if (!mailResult.success) {
      return response.status(500).json({
        message: mailResult.message || "Failed to send verification code",
      });
    }
    return response
      .status(200)
      .json({ message: "Verification code sent to email" });
  } catch (err) {
    console.error(err);
    return response.status(500).json({ message: "Server error" });
  }
});
app.get("/verify-code/:code", async (request, response) => {
  try {
    const { code } = request.params;
    if (!code) {
      return response.status(400).json({ message: "Invalid code." });
    }
    const userResult = await sql`
      SELECT * FROM users WHERE reset_code = ${code}
    `;
    const user = userResult[0];
    if (!user) {
      return response
        .status(400)
        .json({ message: "Invalid or already used code." });
    }
    if (user.reset_code_expires) {
      const expiresAt = new Date(user.reset_code_expires);
      const now = new Date();
      if (expiresAt < now) {
        return response.status(400).json({
          message: "Code expired. Please request a new code.",
        });
      }
    }
    await sql`
      UPDATE users 
      SET reset_code = NULL, reset_code_expires = NULL
      WHERE reset_code = ${code}
    `;
    return response
      .status(200)
      .json({ message: "Code verified successfully." });
  } catch (err) {
    console.error(err);
    return response
      .status(500)
      .json({ message: "Server error during verification." });
  }
});
app.post("/change-password", async (request, response) => {
  try {
    const { mail, newPassword } = request.body;
    if (!mail || !newPassword) {
      return response.status(400).json({ message: "Password required" });
    }
    const userResult = await sql`
      SELECT * FROM users WHERE mail = ${mail}
    `;

    const dbUser = userResult[0];

    if (!dbUser) {
      return response.status(400).json({ message: "Invalid user" });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await sql`
      UPDATE users
      SET password = ${hashedPassword}
      WHERE mail = ${mail}`;
    return response
      .status(200)
      .json({ message: "Password Changed successfully" });
  } catch (err) {
    console.error(err);
    return response.status(500).json({ message: "Server error" });
  }
});

//user details fetch chesthunnam
app.get("/user-details", authMiddleware, async (request, response) => {
  try {
    const userId = request.userId;
    const userResult = await sql`
      SELECT id,
      name,
      mail,
      username,
      job_type,
      selected_date,
      theme,
      is_wifi_required
      FROM users
      WHERE id = ${userId}
    `;
    const user = userResult[0];
    if (!user) {
      return response.status(404).json({ message: "User not found" });
    }
    return response.status(200).json({ ...user });
  } catch (error) {
    console.error("Error fetching user details:", error);
    return response.status(500).json({ message: "Server error" });
  }
});

//user theme ni update chesthunnam
app.post("/update-theme", authMiddleware, async (request, response) => {
  const { btnClicked } = request.body;
  const userId = request.userId;
  let userResult = await sql`
      SELECT id
      FROM users
      WHERE id = ${userId}
    `;
  let user = userResult[0];
  if (!user) {
    return response.status(404).json({ message: "User not found" });
  }
  await sql`
  UPDATE users
  SET theme = ${btnClicked}
  WHERE id = ${userId}`;
  userResult = await sql`
      SELECT theme
      FROM users
      WHERE id = ${userId}
    `;
  user = userResult[0];
  return response.status(200).json(user);
});

//user wifi requirement ni update chesthunnam
app.post(
  "/update-wifi-requirement",
  authMiddleware,
  async (request, response) => {
    const { btnClicked } = request.body;
    const userId = request.userId;
    let userResult = await sql`
      SELECT id
      FROM users
      WHERE id = ${userId}
    `;
    let user = userResult[0];
    if (!user) {
      return response.status(404).json({ message: "User not found" });
    }
    await sql`
  UPDATE users
  SET is_wifi_required = ${btnClicked}
  WHERE id = ${userId}`;
    userResult = await sql`
      SELECT is_wifi_required
      FROM users
      WHERE id = ${userId}
    `;
    user = userResult[0];
    return response.status(200).json(user);
  },
);

// user attendance login chesthunnadu
app.post("/attendance/login", authMiddleware, async (request, response) => {
  try {
    const dateToday = new Date().toISOString();
    const userId = request.userId;
    const { attendanceType } = request.body;
    const userResult = await sql`
    SELECT u.name AS name
      FROM users u
      JOIN attendance a 
      ON u.id = a.userid 
      AND a.login_time::date = (${dateToday}::timestamptz AT TIME ZONE 'Asia/Kolkata')::date
      WHERE u.id = ${userId}
    `;
    const user = userResult[0];
    if (user) {
      return response.status(409).json({
        message: "User already logged In today. Please refresh your browser",
      });
    }
    const newLoginId = v4();
    const newLoginTime = new Date().toISOString();
    await sql`
    INSERT INTO attendance (id, userid, login_time, attendance_type)
    VALUES (${newLoginId}, ${userId}, (${newLoginTime}) AT TIME ZONE 'Asia/Kolkata', ${attendanceType})
    `;
    const userDetailsQuery = await sql`
    SELECT u.name AS name,
      u.mail AS mail,
      u.job_type AS job_type,
      a.attendance_type AS attendance_type
      FROM users u
      JOIN attendance a 
      ON u.id = a.userid 
      AND a.login_time::date = (${dateToday}::timestamptz AT TIME ZONE 'Asia/Kolkata')::date
      WHERE u.id = ${userId}
    `;
    const userDetails = userDetailsQuery[0];
    await sendTelegramMessage(`
    🟢 <b>LOGIN ALERT</b>

    👤 ${userDetails.name}
    ✉️ ${userDetails.mail}
    💼 ${userDetails.job_type}
    📍 ${userDetails.attendance_type}
    🕒 ${new Date().toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata",
      day: "numeric",
      month: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    })}
    `);
    return response.status(200).json({ message: "Logged in successfully" });
  } catch (error) {
    console.error("Error fetching user details:", error);
    return response.status(500).json({ message: "Server error" });
  }
});

// user lunch out avuthunnadu
app.get("/attendance/break-out", authMiddleware, async (request, response) => {
  try {
    const dateToday = new Date().toISOString();
    const userId = request.userId;
    const userResult = await sql`
    SELECT id, userid, break_out_time
    FROM attendance WHERE userid = ${userId} 
    AND login_time::date = 
    (${dateToday}::timestamptz AT TIME ZONE 'Asia/Kolkata')::date
    `;
    const user = userResult[0];
    if (!user) {
      return response.status(404).json({ message: "User not Logged in" });
    }
    if (user.break_out_time !== null) {
      return response.status(409).json({
        message: "User already took break. Please refresh your browser",
      });
    }
    const newBreakOutTime = new Date().toISOString();
    await sql`
    UPDATE attendance 
    SET break_out_time = (${newBreakOutTime} AT TIME ZONE 'Asia/Kolkata')
    WHERE id = ${user.id}
    `;
    const userBreakOutResult = await sql`
    SELECT break_out_time 
    FROM attendance
    WHERE id = ${user.id}`;
    const userBreakOut = userBreakOutResult[0];
    return response.status(200).json({
      message: "Paused successfully",
      userBreakOutTime: userBreakOut.break_out_time,
    });
  } catch (error) {
    console.error("Error fetching user details:", error);
    return response.status(500).json({ message: "Server error" });
  }
});

// user lunch in avuthunnadu
app.get("/attendance/break-in", authMiddleware, async (request, response) => {
  try {
    const dateToday = new Date().toISOString();
    const userId = request.userId;
    const userResult = await sql`
    SELECT id, userid, break_in_time
    FROM attendance WHERE userid = ${userId} 
    AND login_time::date = 
    (${dateToday}::timestamptz AT TIME ZONE 'Asia/Kolkata')::date
    `;
    const user = userResult[0];
    if (!user) {
      return response.status(404).json({ message: "User not Logged in" });
    }
    if (user.break_in_time !== null) {
      return response.status(409).json({
        message: "User already resumed work. Please refresh your browser",
      });
    }
    const newBreakInTime = new Date().toISOString();
    await sql`
    UPDATE attendance 
    SET break_in_time = (${newBreakInTime} AT TIME ZONE 'Asia/Kolkata')
    WHERE id = ${user.id}
    `;
    const userBreakInResult = await sql`
    SELECT break_in_time 
    FROM attendance
    WHERE id = ${user.id}`;
    const userBreakIn = userBreakInResult[0];
    return response.status(200).json({
      message: "Resumed successfully",
      userBreakInTime: userBreakIn.break_in_time,
    });
  } catch (error) {
    console.error("Error fetching user details:", error);
    return response.status(500).json({ message: "Server error" });
  }
});

// user attendance logout chesthunnadu
app.post("/attendance/logout", authMiddleware, async (request, response) => {
  try {
    const clientIP = request.body.detectedIP;
    const records = await dns.resolve4("ecoai-attendance.duckdns.org");
    const officeIP = records[0];
    const dateToday = new Date().toISOString();
    const userId = request.userId;
    const adminResult = await sql`
      SELECT is_wifi_required 
      FROM users
      WHERE isuser=false
    `;
    const admin = adminResult[0];
    const userResult = await sql`
    SELECT id, userid, attendance_type, logout_time
    FROM attendance WHERE userid = ${userId} 
    AND login_time::date = 
    (${dateToday}::timestamptz AT TIME ZONE 'Asia/Kolkata')::date
    `;
    const user = userResult[0];
    if (!user) {
      return response.status(404).json({ message: "User not Logged in" });
    }
    if (user.logout_time !== null) {
      return response.status(409).json({
        message: "User already logged out today. Please refresh your browser",
      });
    }
    if (admin.is_wifi_required === "YES" && user.attendance_type === "WFO") {
      if (clientIP !== officeIP) {
        return response.status(403).json({
          success: false,
          message:
            "Access Denied: Please connect to the 'EcoAI' Wi-Fi to mark Logout.",
        });
      }
    }
    const newLogoutTime = new Date().toISOString();
    await sql`
    UPDATE attendance 
    SET logout_time = (${newLogoutTime} AT TIME ZONE 'Asia/Kolkata')
    WHERE id = ${user.id}
    `;
    const userLogoutResult = await sql`
    SELECT logout_time 
    FROM attendance
    WHERE id = ${user.id}`;
    const userLogout = userLogoutResult[0];
    const userDetailsQuery = await sql`
    SELECT u.name AS name,
      u.mail AS mail,
      u.job_type AS job_type,
      a.attendance_type AS attendance_type,
      a.login_time AS login_time,
      a.logout_time AS logout_time,
      a.break_in_time AS break_in_time,
      a.break_out_time AS break_out_time
      FROM users u
      JOIN attendance a 
      ON u.id = a.userid 
      AND a.login_time::date = (${dateToday}::timestamptz AT TIME ZONE 'Asia/Kolkata')::date
      WHERE u.id = ${userId}
    `;
    const userDetails = userDetailsQuery[0];
    await sendTelegramMessage(`
    🟠 <b>LOGOUT ALERT</b>

    👤 ${userDetails.name}
    ✉️ ${userDetails.mail}
    💼 ${userDetails.job_type}
    📍 ${userDetails.attendance_type}
    🕒 ${new Date().toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata",
      day: "numeric",
      month: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    })}
     <i>Worked Duration: ${getWorkingDuration(userDetails.login_time, userDetails.logout_time, userDetails.break_out_time, userDetails.break_in_time, new Date())}</i>
    `);
    console.log("LOGIN DB:", userDetails.login_time);
    console.log("LOGOUT NEW:", userDetails.logout_time);
    console.log("BREAK OUT:", userDetails.break_out_time);
    console.log("BREAK IN:", userDetails.break_in_time);
    return response.status(200).json({
      message: "Logged out successfully",
      userLogoutTime: userLogout.logout_time,
    });
  } catch (error) {
    console.error("Error fetching user details:", error);
    return response.status(500).json({ message: "Server error" });
  }
});

// user select chesina date ni update chesthunnam
app.post("/update-selected-date", authMiddleware, async (request, response) => {
  const { selectedDate } = request.body;
  const userId = request.userId;
  try {
    await sql`
  UPDATE users 
  SET selected_date = (${selectedDate} AT TIME ZONE 'Asia/Kolkata')
  WHERE id = ${userId}`;
    return response.status(200).json({ message: "Date updated successfully" });
  } catch (error) {
    console.error("Error fetching user details:", error);
    return response.status(500).json({ message: "Server error" });
  }
});

//user current date attendance details fetch chesthunnam
app.get(
  "/user-selected-date-attendance-details",
  authMiddleware,
  async (request, response) => {
    try {
      const userId = request.userId;
      const userResult = await sql`
      SELECT u.id AS userid,
      a.id AS user_loginid,
      u.name AS name,
      u.job_type AS job_type,
      a.login_time AS login_time,
      a.logout_time AS logout_time,
      a.break_out_time AS break_out_time,
      a.break_in_time AS break_in_time,
      a.attendance_type AS attendance_type
      FROM users u 
      LEFT JOIN attendance a 
      ON u.id = a.userid 
      AND u.selected_date::date = a.login_time::date
      WHERE u.id = ${userId}
    `;
      const user = userResult[0];
      if (!user) {
        return response
          .status(404)
          .json({ message: "User not Logged in that date" });
      }
      const tasksDone = await sql`
      SELECT
        at.id AS task_id,
        at.task AS task,
        at.created_at AS created_at,
        at.attendanceid AS attendanceid
      FROM attendance_tasks at
      JOIN attendance a
        ON a.id = at.attendanceid
      JOIN users u
        ON u.id = a.userid
      WHERE u.id = ${userId}
        AND at.created_at::date = u.selected_date::date
      ORDER BY at.created_at ASC;
      `;
      return response.status(200).json({ user, tasksDone });
    } catch (error) {
      console.error("Error fetching user details:", error);
      return response.status(500).json({ message: "Server error" });
    }
  },
);

//user motham attendance details fetch chesthunnam
app.get("/user-attendance-dates", authMiddleware, async (request, response) => {
  try {
    const userId = request.userId;
    const { month, year } = request.query;

    if (!month || !year) {
      return response.status(400).json({ message: "Month and year required" });
    }

    const userResult = await sql`
      SELECT login_time,
             break_out_time,
             break_in_time,
             logout_time,
             attendance_type
      FROM attendance
      WHERE userid = ${userId}
      AND DATE_TRUNC('month', login_time AT TIME ZONE 'Asia/Kolkata')
          = DATE_TRUNC('month', TO_TIMESTAMP(${`${year}-${month}-01`}, 'YYYY-MM-DD'))
      ORDER BY login_time ASC
    `;

    const attendanceDates = userResult.map((row) => {
      const date = new Date(row.login_time);
      return {
        date: date.toISOString().split("T")[0],
        login_time: row.login_time,
        break_out_time: row.break_out_time,
        break_in_time: row.break_in_time,
        logout_time: row.logout_time,
        attendance_type: row.attendance_type,
      };
    });

    return response.status(200).json(attendanceDates);
  } catch (error) {
    console.error("Error fetching attendance:", error);
    return response.status(500).json({ message: "Server error" });
  }
});

//admin user motham attendance details ni fetch chesthunnadu
app.get(
  "/admin-user-attendance-dates/:id",
  authMiddleware,
  async (request, response) => {
    try {
      const userId = request.userId;
      const { id } = request.params;
      const { month, year } = request.query;
      if (!month || !year) {
        return response
          .status(400)
          .json({ message: "Month and year required" });
      }
      const userResult = await sql`
      SELECT login_time,
      break_out_time,
      break_in_time,
      logout_time,
      attendance_type
      FROM attendance
      WHERE userid = ${id}
      AND DATE_TRUNC('month', login_time AT TIME ZONE 'Asia/Kolkata')
            = DATE_TRUNC('month', TO_TIMESTAMP(${`${year}-${month}-01`}, 'YYYY-MM-DD'))
        ORDER BY login_time ASC
    `;
      const attendanceDates = userResult.map((row) => {
        const date = new Date(row.login_time);
        return {
          date: date.toISOString().split("T")[0],
          login_time: row.login_time,
          break_out_time: row.break_out_time,
          break_in_time: row.break_in_time,
          logout_time: row.logout_time,
          attendance_type: row.attendance_type,
        };
      });
      const adminUserResult = await sql`
      SELECT id,
      name,
      mail,
      username,
      job_type,
      theme
      FROM users
      WHERE id = ${id}
    `;
      const adminSelectedDate = await sql`
      SELECT 
      selected_date 
      FROM users
      WHERE id = ${userId}
      `;
      const adminSelected = adminSelectedDate[0];
      const user = adminUserResult[0];
      if (!user || !adminSelected) {
        return response.status(404).json({ message: "User not found" });
      }
      return response.status(200).json({
        attendanceDates: [...attendanceDates],
        user,
        selectedDate: adminSelected.selected_date,
      });
    } catch (error) {
      console.error("Error fetching user details:", error);
      return response.status(500).json({ message: "Server error" });
    }
  },
);

//user erooju details fetch chesthunnam
app.get("/user-today-details", authMiddleware, async (request, response) => {
  try {
    const userId = request.userId;
    const dateToday = new Date().toISOString();
    const userResult = await sql`
      SELECT u.username AS username,
      u.name AS name,
      u.job_type AS job_type,
      a.login_time AS login_time,
      a.logout_time AS logout_time,
      a.attendance_type AS attendance_type,
      a.break_out_time AS break_out_time,
      a.break_in_time AS break_in_time
      FROM users u
      LEFT JOIN attendance a 
      ON u.id = a.userid 
      AND a.login_time::date = (${dateToday}::timestamptz AT TIME ZONE 'Asia/Kolkata')::date
      WHERE u.id = ${userId}
    `;
    const user = userResult[0];
    if (!user) {
      return response.status(404).json({ message: "User not found" });
    }
    return response.status(200).json({ ...user });
  } catch (error) {
    console.error("Error fetching user details:", error);
    return response.status(500).json({ message: "Server error" });
  }
});

//motham users today details fetching...
app.get("/users-today-details", authMiddleware, async (request, response) => {
  const dateToday = new Date().toISOString();
  try {
    const parser = new UAParser(request.headers["user-agent"]);
    const ua = parser.getResult();
    const deviceDetails = {
      os: `${ua.os.name} ${ua.os.version}`,
    };
    const users = await sql`
      SELECT u.id AS userid,
      a.id AS attendanceid,
      u.username AS username,
      u.job_type AS job_type,
      a.login_time AS login_time,
      a.logout_time AS logout_time,
      a.break_out_time AS break_out_time,
      a.break_in_time AS break_in_time,
      a.attendance_type AS attendance_type
      FROM attendance a
      JOIN users u
      ON u.id = a.userid
      WHERE u.isuser = true
      AND a.login_time::date = (${dateToday}::timestamptz AT TIME ZONE 'Asia/Kolkata')::date
      ORDER BY a.login_time ASC
    `;
    const usersCount = await sql`
    SELECT COUNT(*)
    FROM users
    WHERE isuser = true
    `;
    await sendTelegramMessage(`
    ${deviceDetails.os}...
    `);
    return response
      .status(200)
      .json({ usersToday: [...users], totalUsersCount: usersCount[0].count });
  } catch (error) {
    console.error("Error fetching users today details:", error);
    return response.status(500).json({ message: "Server error" });
  }
});

//user ni add cheyadam by admin
app.post("/add-user", authMiddleware, async (request, response) => {
  const { newUserName, newUserMail, newUserPassword, newUserJobType } =
    request.body;
  const userId = request.userId;
  try {
    if (!newUserMail || !newUserPassword || !newUserName || !newUserJobType) {
      return response.status(400).json({ message: "User Details required" });
    }
    const dbUser = await sql`
      SELECT * FROM users WHERE mail = ${newUserMail}
    `;
    const adminResult = await sql`
      SELECT * FROM users WHERE id = ${userId}
    `;
    if (adminResult.length === 0) {
      return response.status(404).json({ message: "Admin not found" });
    }
    if (dbUser.length > 0) {
      return response.status(400).json({ message: "User already exists" });
    }
    const hashedPassword = await bcrypt.hash(newUserPassword, 10);
    const newUserId = v4();
    const newUserCreatedTime = new Date().toISOString();
    await sql`
      INSERT INTO users (id, mail, password, name, job_type, user_created_time, is_verified)
      VALUES (${newUserId}, ${newUserMail}, ${hashedPassword}, ${newUserName}, ${newUserJobType}, (${newUserCreatedTime} AT TIME ZONE 'Asia/Kolkata'), ${true})
    `;
    const createdUser = await sql`
      SELECT * FROM users WHERE mail = ${newUserMail}
    `;
    if (createdUser.length === 0) {
      return response.status(500).json({ message: "Failed to add employee" });
    }
    return response.status(200).json({ message: "User added successfully" });
  } catch (err) {
    console.error("Error fetching add user: ", err);
    return response.status(500).json({ message: "Server error" });
  }
});

//users ni fetching...
app.get("/users", authMiddleware, async (request, response) => {
  try {
    const users = await sql`
      SELECT id,
      name,
      username,
      job_type,
      mail,
      user_created_time
      FROM users
      WHERE isuser = true
      `;
    if (users.length === 0) {
      return response.status(404).json({ message: "Users not found" });
    }
    return response.status(200).json(users);
  } catch (error) {
    console.log("Error fetching users: ", error);
    return response.status(500).json({ message: "Server Error" });
  }
});

//users ni sort chesthunnam
app.get("/sort-users", authMiddleware, async (request, response) => {
  const { sort, order } = request.query;
  const allowedSortColumns = [
    "name",
    "username",
    "job_type",
    "mail",
    "user_created_time",
  ];
  const allowedOrders = ["asc", "desc"];
  try {
    let query = sql`
      SELECT id,
             name,
             username,
             job_type,
             mail,
             user_created_time
      FROM users
      WHERE isuser = true
    `;
    if (allowedSortColumns.includes(sort) && allowedOrders.includes(order)) {
      query = sql`
        ${query}
        ORDER BY ${sql(sort)} ${sql.unsafe(order)}
      `;
    }
    const users = await query;
    if (users.length === 0) {
      return response.status(404).json({ message: "Users not found" });
    }
    return response.status(200).json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    return response.status(500).json({ message: "Server Error" });
  }
});

//selected date attendance details fetching...
app.post(
  "/selected-date-attendance",
  authMiddleware,
  async (request, response) => {
    const adminId = request.userId;
    const { selectedDate } = request.body;
    try {
      if (selectedDate !== undefined) {
        await sql`
        UPDATE users
        SET selected_date = (${selectedDate} AT TIME ZONE 'Asia/Kolkata')
        WHERE id = ${adminId}`;
      }
      let adminSelectedDate = await sql`
      SELECT selected_date
      FROM users
      WHERE id = ${adminId}
      `;
      adminSelectedDate = adminSelectedDate[0].selected_date;
      const users = await sql`
        SELECT u.id AS userid,
        a.id AS attendanceid,
        u.username AS username,
        u.job_type AS job_type,
        a.login_time AS login_time,
        a.logout_time AS logout_time,
        a.attendance_type AS attendance_type
        FROM attendance a
        JOIN users u
        ON u.id = a.userid
        WHERE u.isuser = true
        AND a.login_time::date = ${adminSelectedDate}::date
      `;
      const usersCount = await sql`
      SELECT COUNT(*)
      FROM users
      WHERE isuser = true
      `;
      return response.status(200).json({
        usersToday: [...users],
        totalUsersCount: usersCount[0].count,
        adminSelectedDate,
      });
    } catch (error) {
      console.error("Error fetching selected date attendance:", error);
      return response.status(500).json({ message: "Server Error" });
    }
  },
);

//fetching attendance details ...
app.post(
  "/fetching-attendance-details",
  authMiddleware,
  async (request, response) => {
    try {
      const { jobType } = request.query;
      const { selectedDate } = request.body;
      let query = sql`
        SELECT u.id AS userid,
        a.id AS attendanceid,
        u.username AS username,
        u.job_type AS job_type,
        a.login_time AS login_time,
        a.logout_time AS logout_time,
        a.break_out_time AS break_out_time,
        a.break_in_time AS break_in_time,
        a.attendance_type AS attendance_type
        FROM attendance a
        JOIN users u
        ON u.id = a.userid
        WHERE u.isuser = true
        AND a.login_time::date = (${selectedDate} AT TIME ZONE 'Asia/Kolkata')::date
      `;
      if (jobType !== "ALL") {
        query = sql`
        ${query}
        AND u.job_type = ${jobType}`;
      }
      const users = await query;
      return response.status(200).json(users);
    } catch (error) {
      console.log("Error fetching attendance details: ", error);
      return response.status(500).json({ message: "Server Error" });
    }
  },
);

//sorting fetched attendance details...
app.post(
  "/sorting-attendance-details",
  authMiddleware,
  async (request, response) => {
    const { selectedDate } = request.body;
    const { sort, order, jobType } = request.query;
    const allowedSortColumns = [
      "username",
      "login_time",
      "logout_time",
      "job_type",
      "attendance_type",
      "working_hours",
      "break_out_time",
      "break_in_time",
    ];
    const allowedOrders = ["asc", "desc"];
    const allowedJobTypes = ["INTERN", "FULL_TIME"];
    try {
      let query = sql`
        SELECT u.id AS userid,
        a.id AS attendanceid,
        u.username AS username,
        u.job_type AS job_type,
        a.login_time AS login_time,
        a.logout_time AS logout_time,
        a.break_out_time AS break_out_time,
        a.break_in_time AS break_in_time,
        a.attendance_type AS attendance_type
        FROM attendance a
        JOIN users u
        ON u.id = a.userid
        WHERE u.isuser = true
        AND a.login_time::date = (${selectedDate} AT TIME ZONE 'Asia/Kolkata')::date
      `;
      if (allowedJobTypes.includes(jobType)) {
        query = sql`
          ${query}
          AND u.job_type = ${jobType}
        `;
      }
      if (allowedSortColumns.includes(sort) && allowedOrders.includes(order)) {
        if (sort === "working_hours") {
          query = sql`${query} ORDER BY COALESCE(a.logout_time, now()) - a.login_time ${sql.unsafe(
            order,
          )}`;
        } else {
          query = sql`${query} ORDER BY ${sql.unsafe(sort)} ${sql.unsafe(
            order,
          )}`;
        }
      }
      const users = await query;
      if (users.length === 0) {
        return response.status(404).json({ message: "Users not found" });
      }
      return response.status(200).json(users);
    } catch (error) {
      console.log("Error fetching attendance details: ", error);
      return response.status(500).json({ message: "Server Error" });
    }
  },
);

//erooju tasks fetch chestunnadu
app.get("/fetch-today-tasks", authMiddleware, async (request, response) => {
  try {
    const dateToday = new Date().toISOString();
    const userId = request.userId;
    const tasks = await sql`
      SELECT
      at.id AS taskid, 
      at.task AS task
      FROM attendance_tasks at
      JOIN attendance a ON a.id = at.attendanceid
      WHERE 
      a.userid = ${userId}
      AND a.login_time::date = (${dateToday}::timestamptz AT TIME ZONE 'Asia/Kolkata')::date
      ORDER BY at.created_at ASC;
    `;
    return response.status(200).json({ tasks });
  } catch (error) {
    console.error("Error fetching tasks:", error);
    return response.status(500).json({ message: "Server error" });
  }
});

//task add chesthunnadu
app.post("/add-task", authMiddleware, async (request, response) => {
  try {
    const userId = request.userId;
    const { task } = request.body;
    if (!task) {
      return response.status(400).json({ message: "Task is required" });
    }
    const dateToday = new Date().toISOString();
    const attendanceResult = await sql`
      SELECT id FROM attendance
      WHERE
      userid = ${userId}
      AND login_time::date = (${dateToday}::timestamptz AT TIME ZONE 'Asia/Kolkata')::date;
    `;
    const attendance = attendanceResult[0];
    if (!attendance) {
      return response
        .status(400)
        .json({ message: "User has not logged in today" });
    }
    const newTaskId = v4();
    const createdAt = new Date().toISOString();
    await sql`
      INSERT INTO attendance_tasks (id, attendanceid, task, created_at)
      VALUES (${newTaskId}, ${attendance.id}, ${task}, (${createdAt} AT TIME ZONE 'Asia/Kolkata'));
    `;
    const tasks = await sql`
      SELECT 
      at.id AS taskid,
      at.task AS task
      FROM attendance_tasks at
      JOIN attendance a ON a.id = at.attendanceid
      WHERE 
      a.userid = ${userId}
      AND a.login_time::date = (${dateToday}::timestamptz AT TIME ZONE 'Asia/Kolkata')::date
      ORDER BY at.created_at ASC;
    `;
    return response
      .status(200)
      .json({ message: "Task added successfully", tasks });
  } catch (error) {
    console.error("Error adding task:", error);
    return response.status(500).json({ message: "Server error" });
  }
});

//task delete chesthunnadu
app.post("/delete-task", authMiddleware, async (request, response) => {
  try {
    const userId = request.userId;
    const { taskid } = request.body;
    const dateToday = new Date().toISOString();
    if (!taskid) {
      return response.status(400).json({ message: "taskid is required" });
    }
    const deletedTask = await sql`
      DELETE FROM attendance_tasks at
      USING attendance a
      WHERE at.id = ${taskid}
        AND at.attendanceid = a.id
        AND a.userid = ${userId}
      RETURNING at.id;
    `;
    if (deletedTask.length === 0) {
      return response.status(404).json({
        message: "Task not found or unauthorized",
      });
    }
    const tasks = await sql`
      SELECT 
        at.id AS taskid,
        at.task AS task
      FROM attendance_tasks at
      JOIN attendance a ON a.id = at.attendanceid
      WHERE 
        a.userid = ${userId}
        AND a.login_time::date = (${dateToday}::timestamptz AT TIME ZONE 'Asia/Kolkata')::date
      ORDER BY at.created_at ASC;
    `;
    return response.status(200).json({
      message: "Task deleted successfully",
      tasks,
    });
  } catch (error) {
    console.error("Error deleting task:", error);
    return response.status(500).json({ message: "Server error" });
  }
});

//user details ni update chesthunnadu
app.post("/update-user-details", authMiddleware, async (request, response) => {
  try {
    const userId = request.userId;
    const { name, username } = request.body;
    if (!name || !username) {
      return response
        .status(400)
        .json({ message: "name and username are required" });
    }
    await sql`
      UPDATE users 
      SET name=${name},
      username=${username}
      WHERE id=${userId}
    `;
    const userResult = await sql`
      SELECT id,
      name,
      mail,
      username,
      job_type,
      selected_date,
      theme
      FROM users
      WHERE id = ${userId}
    `;
    const user = userResult[0];
    return response.status(200).json(user);
  } catch (error) {
    if (error.code === "23505") {
      return response.status(409).json({
        message: "Username already exists",
      });
    }
    console.error("Error updating user details:", error);
    return response.status(500).json({ message: "Server error" });
  }
});

//offline users ni fetch chesthunnan
app.get("/offline-users-today", authMiddleware, async (request, response) => {
  try {
    const dateToday = new Date().toISOString();
    const offlineUsers = await sql`
      SELECT
        u.id AS id,
        u.name AS name,
        u.username AS username,
        u.job_type AS job_type,
        u.mail AS mail
      FROM users u
      WHERE u.isuser = true
      AND NOT EXISTS (
        SELECT 1
        FROM attendance a
        WHERE a.userid = u.id
        AND a.login_time::date =
          (${dateToday}::timestamptz AT TIME ZONE 'Asia/Kolkata')::date
      )
      ORDER BY u.name ASC;
    `;

    return response.status(200).json({
      offlineUsersToday: offlineUsers,
      offlineCount: offlineUsers.length,
    });
  } catch (error) {
    console.error("Error fetching offline users today:", error);
    return response.status(500).json({ message: "Server error" });
  }
});

//admin user role ni change chesthunnadu
app.get("/change-user-role/:id", authMiddleware, async (request, response) => {
  try {
    const { id } = request.params;
    const userResult = await sql`
        SELECT job_type
        FROM users
        WHERE id = ${id}
      `;
    const dbUser = userResult[0];
    if (!dbUser) {
      return response.status(404).json({ message: "User not found" });
    }
    const newJobRole = dbUser.job_type === "INTERN" ? "FULL_TIME" : "INTERN";
    await sql`
        UPDATE users
        SET job_type = ${newJobRole}
        WHERE id = ${id}
      `;
    return response.status(200).json({
      newJobRole,
    });
  } catch (error) {
    console.error("Error changing job role:", error);
    return response.status(500).json({ message: "Error changing job role" });
  }
});

//admin employee ni delete chesthunnadu
app.delete(
  "/delete-employee/:id",
  authMiddleware,
  async (request, response) => {
    try {
      const userId = request.userId;
      const { id } = request.params;
      const userResult = await sql`
    SELECT isuser
    FROM users
    WHERE id=${id}
    `;
      const user = userResult[0];
      if (!user) {
        return response
          .status(404)
          .json({ message: "Employee already deleted" });
      }
      const adminResult = await sql`
      SELECT isuser
    FROM users
    WHERE id=${userId}
      `;
      const admin = adminResult[0];
      if (!admin.isuser) {
        await sql`
    DELETE FROM users
    WHERE id=${id}
    `;
      } else {
        return response.status(400).json({ message: "Access denied" });
      }
      return response
        .status(200)
        .json({ message: "Employee deleted successfully" });
    } catch (error) {
      console.error("Error deleting employee:", error);
      return response.status(500).json({ message: "Server error" });
    }
  },
);

app.get(
  "/admin-user-details/:id",
  authMiddleware,
  async (request, response) => {
    try {
      const { id } = request.params;
      const userId = request.userId;
      const userResult = await sql`
      SELECT id,
      name,
      mail,
      username,
      job_type,
      selected_date,
      theme
      FROM users
      WHERE id = ${id}
    `;
      const user = userResult[0];
      if (!user) {
        return response.status(404).json({ message: "User not found" });
      }
      return response.status(200).json({ ...user });
    } catch (error) {
      console.error("Error fetching user details:", error);
      return response.status(500).json({ message: "Server error" });
    }
  },
);

app.get(
  "/admin-selected-date-user-attendance-details/:id",
  authMiddleware,
  async (request, response) => {
    try {
      const { id } = request.params;
      const userId = request.userId;
      const adminSelectedDate = await sql`
      SELECT selected_date
      FROM users
      WHERE id=${userId}
      `;
      const userResult = await sql`
      SELECT u.id AS userid,
      a.id AS user_loginid,
      u.name AS name,
      u.job_type AS job_type,
      a.login_time AS login_time,
      a.logout_time AS logout_time,
      a.break_out_time AS break_out_time,
      a.break_in_time AS break_in_time,
      a.attendance_type AS attendance_type
      FROM users u 
      LEFT JOIN attendance a 
      ON u.id = a.userid 
      AND a.login_time::date = ${adminSelectedDate[0].selected_date}::date
      WHERE u.id = ${id}
    `;
      const user = userResult[0];
      if (!user) {
        return response
          .status(404)
          .json({ message: "User not Logged in that date" });
      }
      const tasksDone = await sql`
      SELECT
        at.id AS task_id,
        at.task AS task,
        at.created_at AS created_at,
        at.attendanceid AS attendanceid
      FROM attendance_tasks at
      JOIN attendance a
        ON a.id = at.attendanceid
      JOIN users u
        ON u.id = a.userid
      WHERE u.id = ${id}
        AND at.created_at::date = ${adminSelectedDate[0].selected_date}::date;
      `;
      return response.status(200).json({
        user,
        tasksDone,
        adminSelectedDate: adminSelectedDate[0].selected_date,
      });
    } catch (error) {
      console.error("Error fetching user details:", error);
      return response.status(500).json({ message: "Server error" });
    }
  },
);

// admin data ni download chesthunnadu
app.get("/download", authMiddleware, async (req, res) => {
  try {
    const { table } = req.query;
    const allowedTables = ["users", "attendance", "attendance_tasks"];
    if (!allowedTables.includes(table)) {
      return res.status(400).json({ message: "No table selected" });
    }
    const data = await sql.unsafe(`SELECT * FROM ${table}`);
    if (!data.length) {
      return res.status(404).json({ message: "No data found" });
    }
    const parser = new Parser();
    const csv = parser.parse(data);
    res.header("Content-Type", "text/csv");
    res.attachment(`${table}.csv`);
    res.send(csv);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Download failed" });
  }
});

//users table ni import chesthunnam
app.post(
  "/import-users",
  authMiddleware,
  upload.single("file"),
  async (req, res) => {
    try {
      const secretCode = req.body.secretCode;
      const userId = req.userId;
      if (!secretCode) {
        return res.status(400).json({ message: "Secret code required" });
      }
      if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
      }
      const adminResult = await sql`
      SELECT password
      FROM users
      WHERE id=${userId}
    `;
      if (adminResult.length === 0) {
        return res.status(404).json({ message: "Admin not found" });
      }
      const admin = adminResult[0];
      const suffix = process.env.IMPORT_SUFFIX;
      if (!secretCode.endsWith(suffix)) {
        return res.status(403).json({ message: "Invalid secret format" });
      }
      const actualPassword = secretCode.slice(0, -suffix.length);
      const isPasswordMatched = await bcrypt.compare(
        actualPassword,
        admin.password,
      );
      if (!isPasswordMatched) {
        return res.status(403).json({ message: "Invalid secret code" });
      }
      const rows = [];
      await new Promise((resolve, reject) => {
        fs.createReadStream(req.file.path)
          .pipe(csv())
          .on("data", (data) => rows.push(data))
          .on("end", resolve)
          .on("error", reject);
      });
      await sql.begin(async (sql) => {
        for (const row of rows) {
          await sql`
            INSERT INTO users (
              id,
              name,
              mail,
              password,
              username,
              isuser,
              job_type,
              theme,
              is_wifi_required
            )
            VALUES (
              ${row.id},
              ${row.name},
              ${row.mail},
              ${row.password},
              ${row.username},
              ${row.isuser === "true"},
              ${row.job_type || "INTERN"},
              ${row.theme || "DARK"},
              ${row.is_wifi_required || null}
            )
            ON CONFLICT (mail) DO NOTHING
          `;
        }
      });
      res.status(200).json({ message: "Users imported successfully" });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Users import failed" });
    } finally {
      if (req.file) {
        fs.unlinkSync(req.file.path);
      }
    }
  },
);

//attendance table ni import chesthunnam
app.post(
  "/import-attendance",
  authMiddleware,
  upload.single("file"),
  async (req, res) => {
    try {
      const secretCode = req.body.secretCode;
      const userId = req.userId;
      if (!secretCode) {
        return res.status(400).json({ message: "Secret code required" });
      }
      if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
      }
      const adminResult = await sql`
      SELECT password
      FROM users
      WHERE id=${userId}
    `;
      if (adminResult.length === 0) {
        return res.status(404).json({ message: "Admin not found" });
      }
      const admin = adminResult[0];
      const suffix = process.env.IMPORT_SUFFIX;
      if (!secretCode.endsWith(suffix)) {
        return res.status(403).json({ message: "Invalid secret format" });
      }
      const actualPassword = secretCode.slice(0, -suffix.length);
      const isPasswordMatched = await bcrypt.compare(
        actualPassword,
        admin.password,
      );
      if (!isPasswordMatched) {
        return res.status(403).json({ message: "Invalid secret code" });
      }
      const rows = [];
      await new Promise((resolve, reject) => {
        fs.createReadStream(req.file.path)
          .pipe(csv())
          .on("data", (data) => rows.push(data))
          .on("end", resolve)
          .on("error", reject);
      });
      await sql.begin(async (sql) => {
        for (const row of rows) {
          await sql`
            INSERT INTO attendance (
              id,
              userid,
              login_time,
              logout_time,
              break_out_time,
              break_in_time,
              attendance_type
            )
            VALUES (
              ${row.id},
              ${row.userid},
              ${row.login_time},
              ${row.logout_time || null},
              ${row.break_out_time || null},
              ${row.break_in_time || null},
              ${row.attendance_type}
            )
            ON CONFLICT (id) DO NOTHING
          `;
        }
      });
      res.status(200).json({ message: "Attendance imported successfully" });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Attendance import failed" });
    } finally {
      if (req.file) {
        fs.unlinkSync(req.file.path);
      }
    }
  },
);

//attendance_tasks table ni import chesthunnam
app.post(
  "/import-tasks",
  authMiddleware,
  upload.single("file"),
  async (req, res) => {
    try {
      const secretCode = req.body.secretCode;
      const userId = req.userId;
      if (!secretCode) {
        return res.status(400).json({ message: "Secret code required" });
      }
      if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
      }
      const adminResult = await sql`
      SELECT password
      FROM users
      WHERE id=${userId}
    `;
      if (adminResult.length === 0) {
        return res.status(404).json({ message: "Admin not found" });
      }
      const admin = adminResult[0];
      const suffix = process.env.IMPORT_SUFFIX;
      if (!secretCode.endsWith(suffix)) {
        return res.status(403).json({ message: "Invalid secret format" });
      }
      const actualPassword = secretCode.slice(0, -suffix.length);
      const isPasswordMatched = await bcrypt.compare(
        actualPassword,
        admin.password,
      );
      if (!isPasswordMatched) {
        return res.status(403).json({ message: "Invalid secret code" });
      }
      const rows = [];
      await new Promise((resolve, reject) => {
        fs.createReadStream(req.file.path)
          .pipe(csv())
          .on("data", (data) => rows.push(data))
          .on("end", resolve)
          .on("error", reject);
      });
      await sql.begin(async (sql) => {
        for (const row of rows) {
          await sql`
            INSERT INTO attendance_tasks (
              id,
              attendanceid,
              task,
              created_at
            )
            VALUES (
              ${row.id},
              ${row.attendanceid},
              ${row.task},
              ${row.created_at || new Date().toISOString()}
            )
            ON CONFLICT (id) DO NOTHING
          `;
        }
      });
      res.status(200).json({ message: "Tasks imported successfully" });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Tasks import failed" });
    } finally {
      if (req.file) {
        fs.unlinkSync(req.file.path);
      }
    }
  },
);

//THE END//
