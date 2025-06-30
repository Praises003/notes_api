# notes_api

# 📓 Secure Notes API – Interswitch Developer Challenge (UI)

This is a secure RESTful API built for a **Personal Notes App** as part of the Interswitch Developer Challenge at the University of Ibadan. It demonstrates best practices in authentication, authorization, and API security using **Node.js, Express, MongoDB, and JWT**.

---

## 🚀 Features

✅ JWT-based Authentication  
✅ OTP Email Verification  
✅ Password Reset with Secure Token  
✅ Input Validation using Zod  
✅ Rate Limiting & Brute-force Protection  
✅ Role-Based Access Control (Admin Only Endpoints)  
✅ Secure Cookie Handling  
✅ Notes CRUD for Authenticated Users

---

## 🧪 How to Run the Project

### 1. Clone the Repository

```bash
git clone https://github.com/Praises003/notes_api.git
cd notes-api

















### 2. Install Dependencies

```bash
npm install
```

### 3. Setup Environment Variables

Create a `.env` file and copy values from `.env.example`.

```bash
cp .env
```

Fill in your MongoDB URI, email credentials, and secret keys.

### 4. Run the App

```bash
npm start
```

The server will run on `the port`.

---

## 🔐 Authentication Flow

1. **Register User** `POST /api/auth/register` e.g "live_url/api/auth/register" this applies to others
2. **Verify Email with OTP** `POST /api/auth/verify-otp` (after registering, ensure you move to this route and verify your email)
3. **Login** `POST /api/auth/login` → returns JWT cookie
4. Use cookie-authenticated requests for:

   * `GET /api/notes`
   * `POST /api/notes`
   * `DELETE /api/notes/:id`
   * `GET /api/all-notes` (admin only)

---

## 📮 Sample API Payloads

### 🔹 Register (POST /api/auth/register)

```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "password123"
}
```

### 🔹 Verify OTP (POST /api/auth/verify-otp)

```json
{
  "userId": "USER_ID_FROM_REGISTER",
  "otp": "123456"
}
```

### 🔹 Login (POST /api/auth/login)

```json
{
  "email": "john@example.com",
  "password": "password123"
}
```

### 🔹 Create Note (POST /api/notes)

```json
{
  "title": "Grocery List",
  "content": "Buy milk, eggs, bread"
}
```

### 🔹 Delete Note (DELETE /api/notes/\:id)

Send `DELETE` request with `:id` of the note.

---

## ✨ Bonus Features

* Role-based access for admin users to view all notes (`/api/all-notes`)
* Email OTP for registration verification
* Password reset system with secure tokens
* Rate limiting to prevent brute-force attacks
* Zod-based validation for strong data integrity

---

## 🧪 Testing

You can test the API using:

* **Postman** – A collection is available [here](#)
* Or use the following cURL commands:

### Register

```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name": "Jane", "email": "jane@example.com", "password": "password123"}'
```

---

## 🛠️ Tech Stack

* Node.js + Express
* MongoDB + Mongoose
* JWT Authentication
* Nodemailer (Gmail SMTP)
* Zod for validation
* dotenv for environment management



### 📄 `.env.`

```env
# Server
PORT=your port server
PRODUCTION=boolean

# MongoDB
MONGO_URI=mongodb+srv://<username>:<password>@cluster.mongodb.net/notes-app

# JWT
JWT_SECRET=your_jwt_secret_key
COOKIE_EXPIRATION_DAYS=expiry date

# OTP
OTP_EXPIRATION_TIME=otp expiry time

# Email (Gmail SMTP)
EMAIL_USER=youremail@gmail.com
EMAIL_PASS=your_app_password
````

